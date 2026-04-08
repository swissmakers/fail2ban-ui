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

# Install required container dependencies
RUN set -eux; \
    apk update; \
    apk upgrade --no-cache; \
    apk add --no-cache \
    bash curl wget whois tzdata jq ca-certificates htop fail2ban geoip openssh-client; \
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
ENTRYPOINT ["/app/fail2ban-ui"]