FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    netcat-traditional \
    metasploit-framework \
    gcc \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /exploits

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
