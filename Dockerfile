# =========================================
#  STAGE 1 -- Build Fail2Ban-UI Binary
# =========================================
FROM golang:1.25.7 AS builder

WORKDIR /app

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy application source code to buildcontainer
COPY . .

# Build Go application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fail2ban-ui ./cmd/server/main.go

# ===================================
#  STAGE 2 -- Standalone UI Version
# ===================================
FROM alpine:3.23 AS standalone-ui

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

# Copy Fail2Ban-UI binary and templates from the build stage
COPY --from=builder /app/fail2ban-ui /app/fail2ban-ui
COPY --from=builder /app/pkg/web/templates /app/templates
COPY --from=builder /app/internal/locales /app/locales
COPY --from=builder /app/pkg/web/static /app/static
RUN chown fail2ban:0 /app/fail2ban-ui && chmod +x /app/fail2ban-ui

EXPOSE 8080
CMD ["/app/fail2ban-ui"]
