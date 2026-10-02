#!/bin/bash
# setup-netns.sh
set -e
ip netns add client_ns
ip netns add server_ns
ip link add veth-c type veth peer name veth-s
ip link set veth-c netns client_ns
ip link set veth-s netns server_ns
ip netns exec client_ns ip addr add 10.99.0.1/24 dev veth-c
ip netns exec server_ns ip addr add 10.99.0.2/24 dev veth-s
ip netns exec client_ns ip link set veth-c up
ip netns exec client_ns ip link set lo up
ip netns exec server_ns ip link set veth-s up
ip netns exec server_ns ip link set lo up
echo "netns 設定完成"