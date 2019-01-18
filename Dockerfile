FROM alpine
MAINTAINER squat <lserven@gmail.com>
RUN echo "@testing http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk add --no-cache ipset iptables wireguard-tools@testing
COPY bin/kg /opt/bin/
ENTRYPOINT ["/opt/bin/kg"]
