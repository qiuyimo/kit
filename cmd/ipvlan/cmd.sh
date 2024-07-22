#!/bin/bash

# 删除
ip netns del sag


# 开启 ip 转发
sysctl -w net.ipv4.ip_forward=1


# 添加网络命名空间，设置 dns，新的网络命名空间名称是 sag
ip netns add sag
mkdir -p /etc/netns/sag && \
echo "nameserver 114.114.114.114" > /etc/netns/sag/resolv.conf


# 为了 ns:root 与 ns:sag 通讯，创建 veth peer 并配置 ip
ip link add veth0_root type veth peer name veth0_sag netns sag
ip link set veth0_root up
ip -n sag link set veth0_sag up
ip addr add 172.16.200.1/24 dev veth0_root
ip -n sag addr add 172.16.200.2/24 dev veth0_sag


# 基于 ens256 作为父网卡，ns:sag 添加 sag_ipvlan_4_24 并配置 ip 为 192.168.4.210/24
ip link add link ens256 name sag_ipvlan_4_24 type ipvlan mode l2
ip link set sag_ipvlan_4_24 netns sag
ip -n sag link set sag_ipvlan_4_24 up
ip -n sag addr add 192.168.4.210/24 brd + dev sag_ipvlan_4_24


# 基于 ens192 作为父网卡，ns:sag 添加 sag_ipvlan_6_24 并配置 ip 为 192.168.6.210/24
ip link add link ens192 name sag_ipvlan_6_24 type ipvlan mode l2
ip link set sag_ipvlan_6_24 netns sag
ip -n sag link set sag_ipvlan_6_24 up
ip -n sag addr add 192.168.6.140/24 brd + dev sag_ipvlan_6_24


# 添加应用 IP 192.168.4.211/24
ip netns exec sag ip addr add 192.168.4.211/24 brd + dev sag_ipvlan_4_24
# ns:root -> 应用ip，如果 ns:root 下没有配置 192.168.4.0/24 的 ip，可以按网段添加路由，否则要用 /32
ip route add 192.168.4.0/24 via 172.16.200.2
ip route add 192.168.4.211/32 via 172.16.200.2
# ns:sag -> ns:root 网卡
ip -n sag route add 192.168.3.97 via 172.16.200.1




#
ipvlanName=ipvlan_2
ipvlanIP=192.168.4.221/24
ip link add link ens256 name $ipvlanName type ipvlan mode l2
ip link set $ipvlanName netns sag
ip -n sag link set $ipvlanName up
ip -n sag addr add $ipvlanIP brd + dev $ipvlanName



#
ipvlanName=ipvlan_1
ipvlanIP=192.168.4.214/24
ip link add link ens256 name $ipvlanName type ipvlan mode l2
ip link set $ipvlanName up
ip addr add $ipvlanIP brd + dev $ipvlanName