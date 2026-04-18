FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    iptables \
    iproute2 \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/setup-routing.sh /usr/local/bin/setup-routing.sh
RUN chmod +x /usr/local/bin/setup-routing.sh

CMD ["/usr/local/bin/setup-routing.sh"]
