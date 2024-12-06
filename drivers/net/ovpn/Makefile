# SPDX-License-Identifier: GPL-2.0
#
# ovpn -- OpenVPN data channel offload in kernel space
#
# Copyright (C) 2020-2024 OpenVPN, Inc.
#
# Author:	Antonio Quartulli <antonio@openvpn.net>

ifdef CONFIG_OVPN_DEBUG
ccflags-y += -DDEBUG -DOVPN_DEBUG
endif

obj-$(CONFIG_OVPN) := ovpn.o
ovpn-y += bind.o
ovpn-y += crypto.o
ovpn-y += crypto_aead.o
ovpn-y += main.o
ovpn-y += io.o
ovpn-y += netlink.o
ovpn-y += netlink-gen.o
ovpn-y += peer.o
ovpn-y += pktid.o
ovpn-y += socket.o
ovpn-y += stats.o
ovpn-y += tcp.o
ovpn-y += udp.o
