#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020-2024 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

#set -x
set -e

UDP_PEERS_FILE=${UDP_PEERS_FILE:-udp_peers.txt}
TCP_PEERS_FILE=${TCP_PEERS_FILE:-tcp_peers.txt}
OVPN_CLI=${OVPN_CLI:-./ovpn-cli}
ALG=${ALG:-aes}
PROTO=${PROTO:-UDP}
FLOAT=${FLOAT:-0}

create_ns() {
	ip netns add peer${1}
}

setup_ns() {
	MODE="P2P"

	if [ ${1} -eq 0 ]; then
		MODE="MP"
		for p in $(seq 1 ${NUM_PEERS}); do
			ip link add veth${p} netns peer0 type veth peer name veth${p} netns peer${p}

			ip -n peer0 addr add 10.10.${p}.1/24 dev veth${p}
			ip -n peer0 link set veth${p} up

			ip -n peer${p} addr add 10.10.${p}.2/24 dev veth${p}
			ip -n peer${p} link set veth${p} up
		done
	fi

	ip netns exec peer${1} ${OVPN_CLI} new_iface tun${1} $MODE
	ip -n peer${1} addr add ${2} dev tun${1}
	ip -n peer${1} link set tun${1} up
}

add_peer() {
	if [ "${PROTO}" == "UDP" ]; then
		if [ ${1} -eq 0 ]; then
			ip netns exec peer0 ${OVPN_CLI} new_multi_peer tun0 1 ${UDP_PEERS_FILE}

			for p in $(seq 1 ${NUM_PEERS}); do
				ip netns exec peer0 ${OVPN_CLI} new_key tun0 ${p} 1 0 ${ALG} 0 \
					data64.key
			done
		else
			ip netns exec peer${1} ${OVPN_CLI} new_peer tun${1} ${1} 1 10.10.${1}.1 1
			ip netns exec peer${1} ${OVPN_CLI} new_key tun${1} ${1} 1 0 ${ALG} 1 \
				data64.key
		fi
	else
		if [ ${1} -eq 0 ]; then
			(ip netns exec peer0 ${OVPN_CLI} listen tun0 1 ${TCP_PEERS_FILE} && {
				for p in $(seq 1 ${NUM_PEERS}); do
					ip netns exec peer0 ${OVPN_CLI} new_key tun0 ${p} 1 0 \
						${ALG} 0 data64.key
				done
			}) &
			sleep 5
		else
			ip netns exec peer${1} ${OVPN_CLI} connect tun${1} ${1} 10.10.${1}.1 1 \
				data64.key
		fi
	fi
}

check_ntfs() {
	# peer 0 notifications
	if [ ${1} -eq 0 ]; then
		for p in $(seq 1 ${NUM_PEERS}); do
			if [ ${p} -eq 1 ]; then
				grep -q "PEER_DEL_NTF ifname=tun0 reason=2 id=1" ${ntfs_file}
			else
				grep -q "PEER_DEL_NTF ifname=tun0 reason=3 id=${p}" ${ntfs_file}
			fi

			if [ "$FLOAT" == "1" ]; then
				part1="PEER_FLOAT_NTF ifname=tun0 peer_id=${p} sa_family=AF_INET"
				part2="address=10.10.${p}.3 port=1"
				grep -q "${part1} ${part2}" ${ntfs_file}
			fi
		done
	# peer 1 notifications
	elif [ ${1} -eq 1 ]; then
		grep -q "PEER_DEL_NTF ifname=tun1 reason=2 id=1" ${ntfs_file}
		grep -q "KEY_SWAP_NTF ifname=tun1 peer_id=1 key_id=1" ${ntfs_file}
	# all other peers notifications
	else
		grep -q "PEER_DEL_NTF ifname=tun${1} reason=3 id=${1}" ${ntfs_file}
	fi
}

cleanup() {
	# first test peers disconnect on down event
	for p in $(seq 0 10); do
		ip -n peer${p} link set tun${p} down 2>/dev/null || true
	done
	for p in $(seq 1 10); do
		ip -n peer0 link del veth${p} 2>/dev/null || true
	done
	for p in $(seq 0 10); do
		ip netns exec peer${p} ${OVPN_CLI} del_iface tun${p} 2>/dev/null || true
		ip netns del peer${p} 2>/dev/null || true
	done
	if [ -f ${ntfs_file} ]; then
		rm -f ${ntfs_file} || true
	fi
}

if [ "${PROTO}" == "UDP" ]; then
	NUM_PEERS=${NUM_PEERS:-$(wc -l ${UDP_PEERS_FILE} | awk '{print $1}')}
else
	NUM_PEERS=${NUM_PEERS:-$(wc -l ${TCP_PEERS_FILE} | awk '{print $1}')}
fi

cleanup

modprobe -r ovpn || true
modprobe -q ovpn pid_bits=17 || true

# trap cleanup EXIT

ntfs_file=$(mktemp)

for p in $(seq 0 ${NUM_PEERS}); do
	create_ns ${p}
done

for p in $(seq 0 ${NUM_PEERS}); do
	setup_ns ${p} 5.5.5.$((${p} + 1))/24
done

for p in $(seq 0 ${NUM_PEERS}); do
	add_peer ${p}
done

for p in $(seq 1 ${NUM_PEERS}); do
	ip netns exec peer0 ${OVPN_CLI} set_peer tun0 ${p} 60 120
	ip netns exec peer${p} ${OVPN_CLI} set_peer tun${p} ${p} 60 120
done

for p in $(seq 1 ${NUM_PEERS}); do
	ip netns exec peer0 ping -qfc 1000 -w 5 5.5.5.$((${p} + 1))
done

# write all netlink notifications to a file
for p in $(seq 0 ${NUM_PEERS}); do
	ip netns exec peer${p} ${OVPN_CLI} listen_mcast 35 1>>${ntfs_file} 2>/dev/null &
	listener_pids[${p}]=$!
done

if [ "$FLOAT" == "1" ]; then
	# make clients float..
	for p in $(seq 1 ${NUM_PEERS}); do
		ip -n peer${p} addr del 10.10.${p}.2/24 dev veth${p}
		ip -n peer${p} addr add 10.10.${p}.3/24 dev veth${p}
	done
	for p in $(seq 1 ${NUM_PEERS}); do
		ip netns exec peer${p} ping -qfc 1000 -w 5 5.5.5.1
	done
fi

ip netns exec peer0 iperf3 -1 -s &
sleep 1
ip netns exec peer1 iperf3 -Z -t 3 -c 5.5.5.1

echo "Adding secondary key and then swap:"
for p in $(seq 1 ${NUM_PEERS}); do
	ip netns exec peer0 ${OVPN_CLI} new_key tun0 ${p} 2 1 ${ALG} 0 data64.key
	ip netns exec peer${p} ${OVPN_CLI} new_key tun${p} ${p} 2 1 ${ALG} 1 data64.key
	ip netns exec peer${p} ${OVPN_CLI} swap_keys tun${p} ${p}
done

sleep 1
echo "Querying all peers:"
ip netns exec peer0 ${OVPN_CLI} get_peer tun0
ip netns exec peer1 ${OVPN_CLI} get_peer tun1

echo "Querying peer 1:"
ip netns exec peer0 ${OVPN_CLI} get_peer tun0 1

echo "Triggering a key swap notification:"
ip netns exec peer0 iperf3 -s -B 5.5.5.1 &
key_swap_iperf_pids[${#key_swap_iperf_pids[@]}]=$!
sleep 1
ip netns exec peer1 iperf3 -Z -b 0 -u -l 64 -t inf -c 5.5.5.1%tun1 &
key_swap_iperf_pids[${#key_swap_iperf_pids[@]}]=$!

while true; do
	if journalctl -kfS -10sec | grep -q "killing key 1 for peer 1"; then
		echo "Key swap notification received"
		for p in ${key_swap_iperf_pids[@]}; do
			kill ${p}
		done
		break
	fi
	sleep 1
done

echo "Deleting consumed key and adding new one:"
ip netns exec peer0 ${OVPN_CLI} del_key tun0 1 1
ip netns exec peer1 ${OVPN_CLI} del_key tun1 1 1
ip netns exec peer0 ${OVPN_CLI} new_key tun0 1 1 2 ${ALG} 0 data64.key
ip netns exec peer1 ${OVPN_CLI} new_key tun1 1 1 2 ${ALG} 1 data64.key

# checking communication after key swap
ip netns exec peer0 ping -qfc 1000 -w 1 5.5.5.2

echo "Querying non-existent peer 10:"
ip netns exec peer0 ${OVPN_CLI} get_peer tun0 10 || true

echo "Deleting peer 1:"
ip netns exec peer0 ${OVPN_CLI} del_peer tun0 1
ip netns exec peer1 ${OVPN_CLI} del_peer tun1 1

echo "Querying keys:"
for p in $(seq 2 ${NUM_PEERS}); do
	ip netns exec peer${p} ${OVPN_CLI} get_key tun${p} ${p} 1
	ip netns exec peer${p} ${OVPN_CLI} get_key tun${p} ${p} 2
done

echo "Deleting keys:"
for p in $(seq 2 ${NUM_PEERS}); do
	ip netns exec peer${p} ${OVPN_CLI} del_key tun${p} ${p} 1
	ip netns exec peer${p} ${OVPN_CLI} del_key tun${p} ${p} 2
done

echo "Setting timeout to 5s MP:"
for p in $(seq 2 ${NUM_PEERS}); do
	ip netns exec peer0 ${OVPN_CLI} set_peer tun0 ${p} 5 5 || true
	ip netns exec peer${p} ${OVPN_CLI} set_peer tun${p} ${p} 0 0
done
# wait for peers to timeout
sleep 7

echo "Setting timeout to 5s P2P:"
for p in $(seq 2 ${NUM_PEERS}); do
	ip netns exec peer${p} ${OVPN_CLI} set_peer tun${p} ${p} 5 5
done
sleep 7
echo "Waiting for listeners to finish:"
for l in ${listener_pids[@]}; do
	wait ${l}
done

echo "Checking received notifications:"
for p in $(seq 0 ${NUM_PEERS}); do
	if [ ! -f ${ntfs_file} ]; then
		echo "missing notification file"
		exit 1
	fi

	check_ntfs ${p}
done

cleanup

modprobe -r ovpn || true
