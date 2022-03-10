#! /usr/bin/sh
# Creates new network namespace and does the bulk of configuration.
# To enable connectivity, assign IP address to eth0 and invoke
# gtpd_ctl to attach gtpd-tap.
unshare -rUn sh -c '
ip link add gtpd-tap type veth peer name eth0;
ethtool -K eth0 tx off; ip link set dev lo up;
ip link set dev gtpd-tap arp off up;
ip link set dev eth0 arp off address 00:00:00:00:00:01 mtu 1400 up;
ip route add default dev eth0;
exec bash'
