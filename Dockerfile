# =========================================
#  STAGE 1 -- Build Fail2Ban-UI Binary
# =========================================
FROM --platform=$BUILDPLATFORM golang:1.25.8 AS builder
WORKDIR /app

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy application source code to buildcontainer
COPY . .

# BuildKit auto-args
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Cross-compile for requested target platform
RUN set -eux; \
    export GOOS="${TARGETOS}"; \
    export GOARCH="${TARGETARCH}"; \
    if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
      export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 go build -trimpath -o fail2ban-ui ./cmd/server/main.go

# ===================================
#  STAGE 2 -- Standalone UI Version
# ===================================
FROM --platform=$TARGETPLATFORM alpine:3.23 AS standalone-ui

# Image metadata (OCI labels). VERSION/REVISION/CREATED are passed by CI.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="Fail2ban-UI" \
      org.opencontainers.image.description="Swiss-made management platform for Fail2ban, supporting local and remote (SSH/agent) Fail2ban servers." \
      org.opencontainers.image.source="https://github.com/swissmakers/fail2ban-ui" \
      org.opencontainers.image.url="https://github.com/swissmakers/fail2ban-ui" \
      org.opencontainers.image.documentation="https://github.com/swissmakers/fail2ban-ui/tree/main/docs" \
      org.opencontainers.image.vendor="Swissmakers GmbH" \
      org.opencontainers.image.authors="Swissmakers GmbH <https://swissmakers.ch>" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.23"

# Install required container dependencies
RUN set -eux; \
    apk update; \
    apk upgrade --no-cache; \
    apk add --no-cache \
    bash curl wget whois tzdata jq ca-certificates htop fail2ban geoip openssh-client tini; \
    test -x /sbin/tini; \
    adduser -D -u 1000 -G root fail2ban

RUN mkdir -p /app /config /config/.ssh \
    /etc/fail2ban/jail.d \
    /etc/fail2ban/filter.d \
    /etc/fail2ban/action.d \
    /var/run/fail2ban \
    /usr/share/GeoIP \
    && touch /etc/fail2ban/jail.local \
    && chown -R fail2ban:0 /app /config /etc/fail2ban /var/run/fail2ban

# Set working directory and volume
WORKDIR /config
VOLUME ["/config"]

ENV CONTAINER=true

# Copy Fail2Ban-UI binary (templates, locales, and static assets are embedded at compile time)
COPY --from=builder /app/fail2ban-ui /app/fail2ban-ui
RUN chown fail2ban:0 /app/fail2ban-ui && chmod +x /app/fail2ban-ui

EXPOSE 8080

# tini runs as PID 1 and reaps orphaned processes
ENTRYPOINT ["/sbin/tini", "--", "/app/fail2ban-ui"]