FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    lsb-release \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN curl -kL --retry 5 --retry-delay 3 "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb" -o /tmp/wazuh-agent.deb && \
    dpkg -i /tmp/wazuh-agent.deb && \
    rm -f /tmp/wazuh-agent.deb

CMD /var/ossec/bin/wazuh-control start && tail -f /dev/null
