// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/skbuff.h>
#include <net/hotdata.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/route.h>
#include <trace/events/sock.h>

#include "ovpnstruct.h"
#include "main.h"
#include "io.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"
#include "tcp.h"

static struct proto ovpn_tcp_prot __ro_after_init;
static struct proto_ops ovpn_tcp_ops __ro_after_init;
static struct proto ovpn_tcp6_prot __ro_after_init;
static struct proto_ops ovpn_tcp6_ops __ro_after_init;

static int ovpn_tcp_parse(struct strparser *strp, struct sk_buff *skb)
{
	struct strp_msg *rxm = strp_msg(skb);
	__be16 blen;
	u16 len;
	int err;

	/* when packets are written to the TCP stream, they are prepended with
	 * two bytes indicating the actual packet size.
	 * Here we read those two bytes and move the skb data pointer to the
	 * beginning of the packet
	 */

	if (skb->len < rxm->offset + 2)
		return 0;

	err = skb_copy_bits(skb, rxm->offset, &blen, sizeof(blen));
	if (err < 0)
		return err;

	len = be16_to_cpu(blen);
	if (len < 2)
		return -EINVAL;

	return len + 2;
}

/* queue skb for sending to userspace via recvmsg on the socket */
static void ovpn_tcp_to_userspace(struct ovpn_peer *peer, struct sock *sk,
				  struct sk_buff *skb)
{
	skb_set_owner_r(skb, sk);
	memset(skb->cb, 0, sizeof(skb->cb));
	skb_queue_tail(&peer->tcp.user_queue, skb);
	peer->tcp.sk_cb.sk_data_ready(sk);
}

static void ovpn_tcp_rcv(struct strparser *strp, struct sk_buff *skb)
{
	struct ovpn_peer *peer = container_of(strp, struct ovpn_peer, tcp.strp);
	struct strp_msg *msg = strp_msg(skb);
	size_t pkt_len = msg->full_len - 2;
	size_t off = msg->offset + 2;
	u8 opcode;

	/* ensure skb->data points to the beginning of the openvpn packet */
	if (!pskb_pull(skb, off)) {
		net_warn_ratelimited("%s: packet too small for peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto err;
	}

	/* strparser does not trim the skb for us, therefore we do it now */
	if (pskb_trim(skb, pkt_len) != 0) {
		net_warn_ratelimited("%s: trimming skb failed for peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto err;
	}

	/* we need the first byte of data to be accessible
	 * to extract the opcode and the key ID later on
	 */
	if (!pskb_may_pull(skb, 1)) {
		net_warn_ratelimited("%s: packet too small to fetch opcode for peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto err;
	}

	/* DATA_V2 packets are handled in kernel, the rest goes to user space */
	opcode = ovpn_opcode_from_skb(skb, 0);
	if (unlikely(opcode != OVPN_DATA_V2)) {
		if (opcode == OVPN_DATA_V1) {
			net_warn_ratelimited("%s: DATA_V1 detected on the TCP stream\n",
					     netdev_name(peer->ovpn->dev));
			goto err;
		}

		/* The packet size header must be there when sending the packet
		 * to userspace, therefore we put it back
		 */
		skb_push(skb, 2);
		ovpn_tcp_to_userspace(peer, strp->sk, skb);
		return;
	}

	/* hold reference to peer as required by ovpn_recv().
	 *
	 * NOTE: in this context we should already be holding a reference to
	 * this peer, therefore ovpn_peer_hold() is not expected to fail
	 */
	if (WARN_ON(!ovpn_peer_hold(peer)))
		goto err;

	ovpn_recv(peer, skb);
	return;
err:
	dev_core_stats_rx_dropped_inc(peer->ovpn->dev);
	kfree_skb(skb);
	ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
}

static int ovpn_tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			    int flags, int *addr_len)
{
	int err = 0, off, copied = 0, ret;
	struct ovpn_socket *sock;
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (!sock || !sock->peer) {
		rcu_read_unlock();
		return -EBADF;
	}
	/* we take a reference to the peer linked to this TCP socket, because
	 * in turn the peer holds a reference to the socket itself.
	 * By doing so we also ensure that the peer stays alive along with
	 * the socket while executing this function
	 */
	ovpn_peer_hold(sock->peer);
	peer = sock->peer;
	rcu_read_unlock();

	skb = __skb_recv_datagram(sk, &peer->tcp.user_queue, flags, &off, &err);
	if (!skb) {
		if (err == -EAGAIN && sk->sk_shutdown & RCV_SHUTDOWN) {
			ret = 0;
			goto out;
		}
		ret = err;
		goto out;
	}

	copied = len;
	if (copied > skb->len)
		copied = skb->len;
	else if (copied < skb->len)
		msg->msg_flags |= MSG_TRUNC;

	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (unlikely(err)) {
		kfree_skb(skb);
		ret = err;
		goto out;
	}

	if (flags & MSG_TRUNC)
		copied = skb->len;
	kfree_skb(skb);
	ret = copied;
out:
	ovpn_peer_put(peer);
	return ret;
}

void ovpn_tcp_socket_detach(struct socket *sock)
{
	struct ovpn_socket *ovpn_sock;
	struct ovpn_peer *peer;

	ovpn_sock = rcu_dereference_sk_user_data(sock->sk);
	if (WARN_ON(!ovpn_sock))
		return;

	peer = ovpn_sock->peer;
	strp_stop(&peer->tcp.strp);

	skb_queue_purge(&peer->tcp.user_queue);

	/* restore CBs that were saved in ovpn_sock_set_tcp_cb() */
	sock->sk->sk_data_ready = peer->tcp.sk_cb.sk_data_ready;
	sock->sk->sk_write_space = peer->tcp.sk_cb.sk_write_space;
	sock->sk->sk_prot = peer->tcp.sk_cb.prot;
	sock->sk->sk_socket->ops = peer->tcp.sk_cb.ops;

	/* drop reference to peer */
	rcu_assign_sk_user_data(sock->sk, NULL);

	/* before canceling any ongoing work we must ensure that CBs
	 * have been reset to prevent workers from being re-armed
	 */
	barrier();

	cancel_work_sync(&peer->tcp.tx_work);
	strp_done(&peer->tcp.strp);
	skb_queue_purge(&peer->tcp.out_queue);

	ovpn_peer_put(peer);
}

static void ovpn_tcp_send_sock(struct ovpn_peer *peer)
{
	struct sk_buff *skb = peer->tcp.out_msg.skb;

	if (!skb)
		return;

	if (peer->tcp.tx_in_progress)
		return;

	peer->tcp.tx_in_progress = true;

	do {
		int ret = skb_send_sock_locked(peer->sock->sock->sk, skb,
					       peer->tcp.out_msg.offset,
					       peer->tcp.out_msg.len);
		if (unlikely(ret < 0)) {
			if (ret == -EAGAIN)
				goto out;

			net_warn_ratelimited("%s: TCP error to peer %u: %d\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id, ret);

			/* in case of TCP error we can't recover the VPN
			 * stream therefore we abort the connection
			 */
			ovpn_peer_del(peer,
				      OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
			break;
		}

		peer->tcp.out_msg.len -= ret;
		peer->tcp.out_msg.offset += ret;
	} while (peer->tcp.out_msg.len > 0);

	if (!peer->tcp.out_msg.len)
		dev_sw_netstats_tx_add(peer->ovpn->dev, 1, skb->len);

	kfree_skb(peer->tcp.out_msg.skb);
	peer->tcp.out_msg.skb = NULL;
	peer->tcp.out_msg.len = 0;
	peer->tcp.out_msg.offset = 0;

out:
	peer->tcp.tx_in_progress = false;
}

static void ovpn_tcp_tx_work(struct work_struct *work)
{
	struct ovpn_peer *peer;

	peer = container_of(work, struct ovpn_peer, tcp.tx_work);

	lock_sock(peer->sock->sock->sk);
	ovpn_tcp_send_sock(peer);
	release_sock(peer->sock->sock->sk);
}

static void ovpn_tcp_send_sock_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	if (peer->tcp.out_msg.skb)
		ovpn_tcp_send_sock(peer);

	if (peer->tcp.out_msg.skb) {
		dev_core_stats_tx_dropped_inc(peer->ovpn->dev);
		kfree_skb(skb);
		return;
	}

	peer->tcp.out_msg.skb = skb;
	peer->tcp.out_msg.len = skb->len;
	peer->tcp.out_msg.offset = 0;
	ovpn_tcp_send_sock(peer);
}

void ovpn_tcp_send_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	u16 len = skb->len;

	*(__be16 *)__skb_push(skb, sizeof(u16)) = htons(len);

	bh_lock_sock(peer->sock->sock->sk);
	if (sock_owned_by_user(peer->sock->sock->sk)) {
		if (skb_queue_len(&peer->tcp.out_queue) >=
		    READ_ONCE(net_hotdata.max_backlog)) {
			dev_core_stats_tx_dropped_inc(peer->ovpn->dev);
			kfree_skb(skb);
			goto unlock;
		}
		__skb_queue_tail(&peer->tcp.out_queue, skb);
	} else {
		ovpn_tcp_send_sock_skb(peer, skb);
	}
unlock:
	bh_unlock_sock(peer->sock->sock->sk);
}

static void ovpn_tcp_release(struct sock *sk)
{
	struct sk_buff_head queue;
	struct ovpn_socket *sock;
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (!sock) {
		rcu_read_unlock();
		goto release;
	}

	peer = sock->peer;

	/* during initialization this function is called before
	 * assigning sock->peer
	 */
	if (unlikely(!peer || !ovpn_peer_hold(peer))) {
		rcu_read_unlock();
		goto release;
	}
	rcu_read_unlock();

	__skb_queue_head_init(&queue);
	skb_queue_splice_init(&peer->tcp.out_queue, &queue);

	while ((skb = __skb_dequeue(&queue)))
		ovpn_tcp_send_sock_skb(peer, skb);

	ovpn_peer_put(peer);
release:
	tcp_release_cb(sk);
}

static int ovpn_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct ovpn_socket *sock;
	int ret, linear = PAGE_SIZE;
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (unlikely(!sock || !sock->peer || !ovpn_peer_hold(sock->peer))) {
		rcu_read_unlock();
		return -EIO;
	}
	peer = sock->peer;
	rcu_read_unlock();

	lock_sock(peer->sock->sock->sk);

	if (msg->msg_flags & ~MSG_DONTWAIT) {
		ret = -EOPNOTSUPP;
		goto peer_free;
	}

	if (peer->tcp.out_msg.skb) {
		ret = -EAGAIN;
		goto peer_free;
	}

	if (size < linear)
		linear = size;

	skb = sock_alloc_send_pskb(sk, linear, size - linear,
				   msg->msg_flags & MSG_DONTWAIT, &ret, 0);
	if (!skb) {
		net_err_ratelimited("%s: skb alloc failed: %d\n",
				    netdev_name(sock->peer->ovpn->dev), ret);
		goto peer_free;
	}

	skb_put(skb, linear);
	skb->len = size;
	skb->data_len = size - linear;

	ret = skb_copy_datagram_from_iter(skb, 0, &msg->msg_iter, size);
	if (ret) {
		kfree_skb(skb);
		net_err_ratelimited("%s: skb copy from iter failed: %d\n",
				    netdev_name(sock->peer->ovpn->dev), ret);
		goto peer_free;
	}

	ovpn_tcp_send_sock_skb(sock->peer, skb);
	ret = size;
peer_free:
	release_sock(peer->sock->sock->sk);
	ovpn_peer_put(peer);
	return ret;
}

static void ovpn_tcp_data_ready(struct sock *sk)
{
	struct ovpn_socket *sock;

	trace_sk_data_ready(sk);

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (likely(sock && sock->peer))
		strp_data_ready(&sock->peer->tcp.strp);
	rcu_read_unlock();
}

static void ovpn_tcp_write_space(struct sock *sk)
{
	struct ovpn_socket *sock;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (likely(sock && sock->peer)) {
		schedule_work(&sock->peer->tcp.tx_work);
		sock->peer->tcp.sk_cb.sk_write_space(sk);
	}
	rcu_read_unlock();
}

static void ovpn_tcp_build_protos(struct proto *new_prot,
				  struct proto_ops *new_ops,
				  const struct proto *orig_prot,
				  const struct proto_ops *orig_ops);

/* Set TCP encapsulation callbacks */
int ovpn_tcp_socket_attach(struct socket *sock, struct ovpn_peer *peer)
{
	struct strp_callbacks cb = {
		.rcv_msg = ovpn_tcp_rcv,
		.parse_msg = ovpn_tcp_parse,
	};
	int ret;

	/* make sure no pre-existing encapsulation handler exists */
	if (sock->sk->sk_user_data)
		return -EBUSY;

	/* only a fully connected socket is expected. Connection should be
	 * handled in userspace
	 */
	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		net_err_ratelimited("%s: provided TCP socket is not in ESTABLISHED state: %d\n",
				    netdev_name(peer->ovpn->dev),
				    sock->sk->sk_state);
		return -EINVAL;
	}

	ret = strp_init(&peer->tcp.strp, sock->sk, &cb);
	if (ret < 0) {
		DEBUG_NET_WARN_ON_ONCE(1);
		release_sock(sock->sk);
		return ret;
	}

	INIT_WORK(&peer->tcp.tx_work, ovpn_tcp_tx_work);
	__sk_dst_reset(sock->sk);
	skb_queue_head_init(&peer->tcp.user_queue);
	skb_queue_head_init(&peer->tcp.out_queue);

	/* save current CBs so that they can be restored upon socket release */
	peer->tcp.sk_cb.sk_data_ready = sock->sk->sk_data_ready;
	peer->tcp.sk_cb.sk_write_space = sock->sk->sk_write_space;
	peer->tcp.sk_cb.prot = sock->sk->sk_prot;
	peer->tcp.sk_cb.ops = sock->sk->sk_socket->ops;

	/* assign our static CBs and prot/ops */
	sock->sk->sk_data_ready = ovpn_tcp_data_ready;
	sock->sk->sk_write_space = ovpn_tcp_write_space;

	if (sock->sk->sk_family == AF_INET) {
		sock->sk->sk_prot = &ovpn_tcp_prot;
		sock->sk->sk_socket->ops = &ovpn_tcp_ops;
	} else {
		sock->sk->sk_prot = &ovpn_tcp6_prot;
		sock->sk->sk_socket->ops = &ovpn_tcp6_ops;
	}

	/* avoid using task_frag */
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_use_task_frag = false;

	/* enqueue the RX worker */
	strp_check_rcv(&peer->tcp.strp);

	return 0;
}

static void ovpn_tcp_close(struct sock *sk, long timeout)
{
	struct ovpn_socket *sock;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (sock && sock->peer) {
		strp_stop(&sock->peer->tcp.strp);
		ovpn_peer_del(sock->peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
	}
	rcu_read_unlock();
	tcp_close(sk, timeout);
}

static __poll_t ovpn_tcp_poll(struct file *file, struct socket *sock,
			      poll_table *wait)
{
	__poll_t mask = datagram_poll(file, sock, wait);
	struct ovpn_socket *ovpn_sock;

	rcu_read_lock();
	ovpn_sock = rcu_dereference_sk_user_data(sock->sk);
	if (ovpn_sock && ovpn_sock->peer &&
	    !skb_queue_empty(&ovpn_sock->peer->tcp.user_queue))
		mask |= EPOLLIN | EPOLLRDNORM;
	rcu_read_unlock();

	return mask;
}

static void ovpn_tcp_build_protos(struct proto *new_prot,
				  struct proto_ops *new_ops,
				  const struct proto *orig_prot,
				  const struct proto_ops *orig_ops)
{
	memcpy(new_prot, orig_prot, sizeof(*new_prot));
	memcpy(new_ops, orig_ops, sizeof(*new_ops));
	new_prot->recvmsg = ovpn_tcp_recvmsg;
	new_prot->sendmsg = ovpn_tcp_sendmsg;
	new_prot->close = ovpn_tcp_close;
	new_prot->release_cb = ovpn_tcp_release;
	new_ops->poll = ovpn_tcp_poll;
}

/* Initialize TCP static objects */
void __init ovpn_tcp_init(void)
{
	ovpn_tcp_build_protos(&ovpn_tcp_prot, &ovpn_tcp_ops, &tcp_prot,
			      &inet_stream_ops);

#if IS_ENABLED(CONFIG_IPV6)
	ovpn_tcp_build_protos(&ovpn_tcp6_prot, &ovpn_tcp6_ops, &tcpv6_prot,
			      &inet6_stream_ops);
#endif
}
