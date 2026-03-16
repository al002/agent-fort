FROM alpine:3.21

RUN apk add --no-cache \
    build-base \
    file \
    libcap-dev \
    libcap-static \
    libseccomp-dev \
    libseccomp-static \
    linux-headers \
    meson \
    musl-dev \
    ninja \
    pkgconf

COPY tools/xtask/bwrap/build-bwrap.sh /usr/local/bin/build-bwrap.sh
RUN chmod 0755 /usr/local/bin/build-bwrap.sh

ENTRYPOINT ["/usr/local/bin/build-bwrap.sh"]
