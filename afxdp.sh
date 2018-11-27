#!/bin/bash
set -x 

ulimit -l unlimited
rm -f /usr/local/etc/openvswitch/conf.db
ovsdb-tool create /usr/local/etc/openvswitch/conf.db /root/ovs/vswitchd/vswitch.ovsschema

ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach

#umount /sys/fs/bpf
#mount -t bpf none /sys/fs/bpf/
#mkdir -p /sys/fs/bpf/ovs/
> /root/ovs/ovs-vswitchd.log
ovs-vsctl --no-wait init 
if [ "$1" == "gdb" ]; then
    gdb -ex=r --args ovs-vswitchd --no-chdir --pidfile --log-file=/root/ovs/ovs-vswitchd.log -vvconn -vofproto_dpif -vunixctl --disable-system
else
    ovs-vswitchd --no-chdir --pidfile --log-file=/root/ovs/ovs-vswitchd.log -vvconn -vofproto_dpif -vunixctl --disable-system --detach
fi
#ovs-vsctl -- add-br br0 -- set Bridge br0 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14,OpenFlow15 fail-mode=secure datapath_type=netdev 
ovs-vsctl -- add-br br0 -- set Bridge br0 datapath_type=netdev
ip netns add at_ns0 
#ovs-appctl vlog/set dbg
#ovs-appctl vlog/set poll_loop::off
ovs-appctl vlog/set netdev_afxdp::dbg

ip link add p0 type veth peer name afxdp-p0 
ip link set p0 netns at_ns0
ip link set dev afxdp-p0 up
ovs-vsctl add-port br0 afxdp-p0 -- \
                set interface afxdp-p0 external-ids:iface-id="p0" type="afxdp"
ip netns exec at_ns0 sh << NS_EXEC_HEREDOC
ip addr add "10.1.1.1/24" dev p0
ip link set dev p0 up
NS_EXEC_HEREDOC

ip netns add at_ns1
ip link add p1 type veth peer name afxdp-p1 
ip link set p1 netns at_ns1
ip link set dev afxdp-p1 up
ovs-vsctl add-port br0 afxdp-p1 -- \
                set interface afxdp-p1 external-ids:iface-id="p1" type="afxdp" 

ip netns exec at_ns1 sh << NS_EXEC_HEREDOC
ip addr add "10.1.1.2/24" dev p1
ip link set dev p1 up
NS_EXEC_HEREDOC

#ovs-ofctl del-flows br0
#ovs-ofctl add-flow br0 "in_port=1, actions=NORMAL"
#ovs-ofctl add-flow br0 "in_port=afxdp-p1, actions=output:afxdp-p0"
#ovs-ofctl add-flow br0 "in_port=afxdp-p0, actions=output:afxdp-p1"
#ovs-ofctl add-flow br0 "in_port=afxdp-p1, actions=output:afxdp-p0"
ovs-ofctl dump-flows br0
ovs-ofctl dump-ports-desc br0
ip netns exec at_ns0 ping 10.1.1.2
exit

ip netns exec at_ns1 tcpdump -w ns1.pcap &
sleep 1
ip netns exec at_ns0 arping -c 10 10.1.1.2
ip netns exec at_ns0 ping -i .2 10.1.1.2
ovs-appctl dpif/dump-flows br0
ovs-ofctl dump-flows br0
ovs-vsctl -- --columns=name,statistics list Interface



exit
ip addr add 10.1.1.2/24 dev br0
ip link set dev br0 up
tcpdump -i afxdp-p0 -w afxdp-p0.pcap &
ip netns exec at_ns0 tcpdump -i p0 -w p0.pcap &
sleep 1
ping 10.1.1.1

exit


