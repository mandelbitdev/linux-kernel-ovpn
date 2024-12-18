/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_UDP_H_
#define _NET_OVPN_UDP_H_

struct ovpn_priv;
struct socket;

int ovpn_udp_socket_attach(struct socket *sock, struct ovpn_priv *ovpn);
void ovpn_udp_socket_detach(struct socket *sock);

#endif /* _NET_OVPN_UDP_H_ */
