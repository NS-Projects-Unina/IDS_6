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

# Wazuh agent: install at runtime if not present
if [ ! -f /var/ossec/bin/wazuh-agentd ]; then
  echo "[wazuh-agent] Download wazuh-agent 4.7.5..."
  curl -kL --retry 5 --retry-delay 3 \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb" \
    -o /tmp/wazuh-agent.deb
  # Pre-create user/group so dpkg postinstall succeeds
  groupadd wazuh 2>/dev/null || true
  useradd -g wazuh -M -s /sbin/nologin wazuh 2>/dev/null || true
  WAZUH_MANAGER=10.0.2.30 WAZUH_MANAGER_PORT=1514 WAZUH_PROTOCOL=tcp \
    dpkg -i /tmp/wazuh-agent.deb 2>&1 || true
  rm -f /tmp/wazuh-agent.deb
  echo "[wazuh-agent] Installazione completata."
fi

# Enrollment (solo se non già registrato)
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "[wazuh-agent] Enrollment su 10.0.2.30:1515..."
  until /var/ossec/bin/agent-auth -m 10.0.2.30 -p 1515 -A defense-nids -F 0 2>/dev/null; do
    echo "[wazuh-agent] Manager non ancora pronto, riprovo tra 5s..."
    sleep 5
  done
  echo "[wazuh-agent] Enrollment completato."
fi

# Assicura che ar.conf sia presente (il manager lo sincronizza, ma potrebbe tardare)
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
