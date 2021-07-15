ARG FROM=alpine
FROM $FROM AS cni
ARG GOARCH=amd64
ARG CNI_PLUGINS_VERSION=v0.9.1
RUN apk add --no-cache curl && \
    curl -Lo cni.tar.gz https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-$GOARCH-$CNI_PLUGINS_VERSION.tgz && \
    tar -xf cni.tar.gz

FROM $FROM
ARG GOARCH
ARG ALPINE_VERSION=v3.12
LABEL maintainer="squat <lserven@gmail.com>"
RUN echo -e "https://alpine.global.ssl.fastly.net/alpine/$ALPINE_VERSION/main\nhttps://alpine.global.ssl.fastly.net/alpine/$ALPINE_VERSION/community" > /etc/apk/repositories && \
    apk add --no-cache ipset iptables ip6tables wireguard-tools graphviz font-bitstream-type1
COPY --from=cni bridge host-local loopback portmap /opt/cni/bin/
COPY bin/linux/$GOARCH/kg /opt/bin/
ENTRYPOINT ["/opt/bin/kg"]
