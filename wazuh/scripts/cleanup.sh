#!/bin/bash
# Rimuove PID e lock stale da run precedenti prima che wazuh-control parta
rm -rf /var/ossec/var/run/*.pid \
        /var/ossec/var/run/*.lock \
        /var/ossec/var/start-script-lock \
        2>/dev/null || true
