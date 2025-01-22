/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_TCP_H_
#define _NET_OVPN_TCP_H_

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "peer.h"
#include "skb.h"
#include "socket.h"

void __init ovpn_tcp_init(void);

int ovpn_tcp_socket_attach(struct socket *sock, struct ovpn_peer *peer);
void ovpn_tcp_socket_detach(struct ovpn_socket *ovpn_sock);

/* Prepare skb and enqueue it for sending to peer.
 *
 * Preparation consist in prepending the skb payload with its size.
 * Required by the OpenVPN protocol in order to extract packets from
 * the TCP stream on the receiver side.
 */
void ovpn_tcp_send_skb(struct ovpn_peer *peer, struct sk_buff *skb);

#endif /* _NET_OVPN_TCP_H_ */
