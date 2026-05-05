FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    iptables \
    iproute2 \
    iputils-ping \
    procps \
    curl \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Installazione Wazuh Agent
RUN groupadd wazuh && useradd -g wazuh -M -s /sbin/nologin wazuh && \
    curl -kL --retry 5 --retry-delay 3 "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb" -o /tmp/wazuh-agent.deb && \
    WAZUH_MANAGER=10.0.2.30 WAZUH_MANAGER_PORT=1514 WAZUH_PROTOCOL=tcp dpkg -i /tmp/wazuh-agent.deb || true && \
    rm -f /tmp/wazuh-agent.deb


COPY scripts/setup-routing.sh /usr/local/bin/setup-routing.sh
RUN chmod +x /usr/local/bin/setup-routing.sh

COPY suricata/suricata.yaml /etc/suricata/suricata.yaml
COPY suricata/rules/local.rules /etc/suricata/rules/local.rules

# Script custom di Active Response: legge src_ip dal JSON Suricata
COPY custom-firewall-drop /var/ossec/active-response/bin/custom-firewall-drop
RUN chmod 750 /var/ossec/active-response/bin/custom-firewall-drop && \
    chown root:wazuh /var/ossec/active-response/bin/custom-firewall-drop

CMD ["/usr/local/bin/setup-routing.sh"]
