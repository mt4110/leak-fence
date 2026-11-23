FROM postgres:17-alpine@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73
# The upstream entrypoint uses gosu to drop privileges to the postgres user.
# Alpine's su-exec provides that behavior without the old Go runtime.
RUN apk upgrade --no-cache \
    && apk add --no-cache su-exec \
    && ln -sf /sbin/su-exec /usr/local/bin/gosu
