udhcpc -i eth0 -s /sbin/udhcpc.sh -p /var/run/udhcpc.pid&

echo " ">/var/udhcpd.leases
brctl addbr br0
brctl addif br0 vmc0

ifconfig br0 192.168.123.1
udhcpd /etc/udhcpd.conf&
