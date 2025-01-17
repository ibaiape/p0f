#
# Adapted from https://github.com/telekom-security/tpotce/tree/master/docker/p0f
#

FROM alpine:latest
#
# Install packages
RUN apk -U --no-cache add bash build-base jansson jansson-dev libcap libpcap libpcap-dev json-c-dev
#
# Setup user, groups and configs
RUN addgroup -g 2000 p0f && adduser -S -s /bin/bash -u 2000 -D -g 2000 p0f
#
# Add source
ADD . /opt/p0f
#
# Download and compile p0f
RUN cd /opt/p0f && ./build.sh && setcap cap_sys_chroot,cap_setgid,cap_net_raw=+ep /opt/p0f/p0f
#
# Clean up
RUN apk del --purge build-base jansson-dev libpcap-dev
RUN rm -rf /root/* && \
    rm -rf /var/cache/apk/*
#
# Start suricata
WORKDIR /opt/p0f
USER p0f:p0f
CMD exec /opt/p0f/p0f -u p0f -j -o /var/log/p0f/p0f.json -i eth0 -p > /dev/null