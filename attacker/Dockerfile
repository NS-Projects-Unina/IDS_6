FROM kalilinux/kali-rolling

RUN echo 'deb [trusted=yes] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware' \
        > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
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
