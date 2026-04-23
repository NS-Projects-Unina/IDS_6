#!/bin/bash
set -e

sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

iptables -F FORWARD
iptables -P FORWARD ACCEPT
iptables -t nat -F POSTROUTING

iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.2.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j MASQUERADE

suricata -c /etc/suricata/suricata.yaml --af-packet -D --pidfile /var/run/suricata.pid

exec tail -f /dev/null
