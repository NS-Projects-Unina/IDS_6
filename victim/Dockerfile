FROM tleemcjr/metasploitable2

RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y build-essential libc6-dev wget

COPY ossec.tar.gz /tmp/ossec.tar.gz

RUN cd /tmp && \
    tar -zxf ossec.tar.gz && \
    cd ossec-hids-2.9.3 && \
    echo "USER_LANGUAGE=\"en\"" > etc/preloaded-vars.conf && \
    echo "USER_NO_STOP=\"y\"" >> etc/preloaded-vars.conf && \
    echo "USER_INSTALL_TYPE=\"agent\"" >> etc/preloaded-vars.conf && \
    echo "USER_DIR=\"/var/ossec\"" >> etc/preloaded-vars.conf && \
    echo "USER_ENABLE_ACTIVE_RESPONSE=\"y\"" >> etc/preloaded-vars.conf && \
    echo "USER_ENABLE_SYSCHECK=\"y\"" >> etc/preloaded-vars.conf && \
    echo "USER_ENABLE_ROOTCHECK=\"y\"" >> etc/preloaded-vars.conf && \
    echo "USER_AGENT_SERVER_IP=\"10.0.2.30\"" >> etc/preloaded-vars.conf && \
    ./install.sh
