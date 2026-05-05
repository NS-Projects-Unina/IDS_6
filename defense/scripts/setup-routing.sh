#!/bin/bash
set -e

sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

iptables -F FORWARD
iptables -P FORWARD ACCEPT
iptables -t nat -F POSTROUTING

iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.2.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j MASQUERADE

rm -f /var/run/suricata.pid
suricata -c /etc/suricata/suricata.yaml --af-packet -D --pidfile /var/run/suricata.pid

# Enrollment: eseguito solo se client.keys e' assente o vuoto
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "[wazuh-agent] Avvio enrollment su 10.0.2.30:1515..."
  until /var/ossec/bin/agent-auth -m 10.0.2.30 -p 1515 -A defense-nids 2>/dev/null; do
    echo "[wazuh-agent] Manager non ancora pronto (o in attesa), riprovo tra 5s..."
    sleep 5
  done
  echo "[wazuh-agent] Enrollment completato."
fi

# Assicura che ar.conf sia presente prima di avviare l'agent
mkdir -p /var/ossec/etc/shared
if [ ! -s /var/ossec/etc/shared/ar.conf ]; then
  cat > /var/ossec/etc/shared/ar.conf << 'AREOF'
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
firewall-drop600 - firewall-drop - 600
AREOF
  chown root:wazuh /var/ossec/etc/shared/ar.conf
fi

/var/ossec/bin/wazuh-control start
echo "[wazuh-agent] Agent avviato."

exec tail -f /dev/null
