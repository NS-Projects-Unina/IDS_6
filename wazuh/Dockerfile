FROM wazuh/wazuh-manager:4.7.5

COPY filebeat/filebeat.yml /etc/filebeat/filebeat.yml
COPY filebeat/fields.yml /etc/filebeat/fields.yml
RUN chmod 644 /etc/filebeat/filebeat.yml /etc/filebeat/fields.yml && \
    chown root:root /etc/filebeat/filebeat.yml /etc/filebeat/fields.yml

COPY scripts/cleanup.sh /etc/cont-init.d/1b-cleanup.sh
RUN chmod +x /etc/cont-init.d/1b-cleanup.sh
