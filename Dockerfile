ARG FROM=alpine
FROM alpine AS cni
ARG GOARCH
RUN apk add --no-cache curl && \
    curl -Lo cni.tar.gz https://github.com/containernetworking/plugins/releases/download/v0.7.5/cni-plugins-$GOARCH-v0.7.5.tgz && \
    tar -xf cni.tar.gz

FROM $FROM
ARG GOARCH
LABEL maintainer="squat <lserven@gmail.com>"
RUN echo -e "https://dl-3.alpinelinux.org/alpine/edge/main\nhttps://dl-3.alpinelinux.org/alpine/edge/community" > /etc/apk/repositories && \
    apk add --no-cache ipset iptables ip6tables wireguard-tools
COPY --from=cni bridge host-local loopback portmap /opt/cni/bin/
COPY bin/$GOARCH/kg /opt/bin/
ENTRYPOINT ["/opt/bin/kg"]
