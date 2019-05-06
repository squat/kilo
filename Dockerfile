FROM alpine AS cni
RUN apk add --no-cache curl && \
    curl -Lo cni.tar.gz https://github.com/containernetworking/plugins/releases/download/v0.7.5/cni-plugins-amd64-v0.7.5.tgz && \
    tar -xf cni.tar.gz

FROM alpine
MAINTAINER squat <lserven@gmail.com>
RUN echo "@testing http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk add --no-cache ipset iptables wireguard-tools@testing
COPY --from=cni bridge host-local loopback portmap /opt/cni/bin/
COPY bin/kg /opt/bin/
ENTRYPOINT ["/opt/bin/kg"]
