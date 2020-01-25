#!/bin/sh

set -x

ip link add name veth_pod0_in numrxqueues 20 numtxqueues 20 type veth peer name veth_pod0_out numrxqueues 20 numtxqueues 20
ip link add name veth_pod1_in numrxqueues 20 numtxqueues 20 type veth peer name veth_pod1_out numrxqueues 20 numtxqueues 20

ethtool -K veth_pod0_in tx off
ethtool -K veth_pod1_in tx off

ip addr add 192.168.201.1/24 dev veth_pod0_in
ip addr add 192.168.202.1/24 dev veth_pod1_in
# ip addr del 192.168.201.1 dev veth_pod0_in
# ip addr del 192.168.202.1 dev veth_pod1_in

ip netns add pod0
ip link set veth_pod0_out netns pod0
ip netns add pod1
ip link set veth_pod1_out netns pod1

ip netns exec pod0  ethtool -K veth_pod0_out tx off
ip netns exec pod1  ethtool -K veth_pod1_out tx off

ip netns exec pod0  ip addr add 192.168.201.2/24 dev veth_pod0_out
ip netns exec pod1  ip addr add 192.168.202.2/24 dev veth_pod1_out

ip netns exec pod0  ip link set veth_pod0_out up
ip netns exec pod1  ip link set veth_pod1_out up
ip link set veth_pod0_in up
ip link set veth_pod1_in up

ip netns exec pod0  ip route add default via 192.168.201.1 dev veth_pod0_out
ip netns exec pod1  ip route add default via 192.168.202.1 dev veth_pod1_out
