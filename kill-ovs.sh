#!/bin/bash
ovs-vsctl del-port br0 enp2s0
ovs-vsctl del-port br0 eth5
#ovs-dpctl del-dp ovs-system 
#ovs-dpctl del-dp ovs-netdev
#ovs-dpctl del-dp ovs-dummy
ovs-appctl -t ovsdb-server exit
ovs-appctl -t ovs-vswitchd exit
killall ovs-vswitchd
ip netns del at_ns0
ip netns del at_ns1
ip link del br0
ip link del br1
ip link del br-int
ip link del br-underlay
ip link del ovs-netdev
ip link del ovs-system
ip link del p0
ip link del ovs-p0

ip link del p1
ip link del ovs-p1
ip link del afxdp-p0
ip link del afxdp-p1
ip link set dev enp2s0 xdp off
umount /sys/fs/bpf
