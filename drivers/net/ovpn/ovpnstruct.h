/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNSTRUCT_H_
#define _NET_OVPN_OVPNSTRUCT_H_

#include <linux/workqueue.h>
#include <net/gro_cells.h>
#include <net/net_trackers.h>
#include <uapi/linux/if_link.h>
#include <uapi/linux/ovpn.h>

/**
 * struct ovpn_priv - per ovpn interface state
 * @dev: the actual netdev representing the tunnel
 * @dev_tracker: reference tracker for associated dev
 * @registered: whether dev is still registered with netdev or not
 * @mode: device operation mode (i.e. p2p, mp, ..)
 * @lock: protect this object
 * @peer: in P2P mode, this is the only remote peer
 * @gro_cells: pointer to the Generic Receive Offload cell
 */
struct ovpn_priv {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	bool registered;
	enum ovpn_mode mode;
	spinlock_t lock; /* protect writing to the ovpn_priv object */
	struct ovpn_peer __rcu *peer;
	struct gro_cells gro_cells;
};

#endif /* _NET_OVPN_OVPNSTRUCT_H_ */
