FROM --platform=$BUILDPLATFORM docker.io/nixos/nix:2.33.3 AS builder

COPY . /tmp/build
WORKDIR /tmp/build

ARG BUILDOS
ARG BUILDARCH
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

RUN VERSION="$VERSION" nix \
    --extra-experimental-features "nix-command flakes" \
    --option filter-syscalls false \
    build --impure ".#kilo-cross-$TARGETOS-$TARGETARCH"
RUN ln -s ../bin result/bin/"$BUILDOS"_"$BUILDARCH"

FROM alpine:3.20 AS cni
ARG TARGETARCH
ARG CNI_PLUGINS_VERSION=v1.9.0
RUN apk add --no-cache curl && \
    curl -Lo cni.tar.gz https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-$TARGETARCH-$CNI_PLUGINS_VERSION.tgz && \
    tar -xf cni.tar.gz

FROM alpine:3.20
ARG TARGETOS
ARG TARGETARCH
ARG ALPINE_VERSION=v3.20
LABEL maintainer="squat <lserven@gmail.com>"
RUN echo -e "https://alpine.global.ssl.fastly.net/alpine/$ALPINE_VERSION/main\nhttps://alpine.global.ssl.fastly.net/alpine/$ALPINE_VERSION/community" > /etc/apk/repositories && \
    apk add --no-cache ipset iptables ip6tables graphviz font-noto
COPY --from=cni bridge host-local loopback portmap /opt/cni/bin/
ADD https://raw.githubusercontent.com/kubernetes-sigs/iptables-wrappers/e139a115350974aac8a82ec4b815d2845f86997e/iptables-wrapper-installer.sh /
RUN chmod 700 /iptables-wrapper-installer.sh && /iptables-wrapper-installer.sh --no-sanity-check
COPY --from=builder /tmp/build/result/bin/"$TARGETOS"_"$TARGETARCH"/kg /opt/bin/kg
COPY --from=builder /tmp/build/result/bin/"$TARGETOS"_"$TARGETARCH"/kgctl /opt/bin/kgctl
ENTRYPOINT ["/opt/bin/kg"]
