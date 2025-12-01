# =========================================
#  STAGE 1: Build Fail2Ban UI Binary
# =========================================
FROM golang:1.23 AS builder

WORKDIR /app

# Copy module files and download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the application source code
COPY . .

# Build Go application (as static binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fail2ban-ui ./cmd/server/main.go

# ===================================
#  STAGE 2: Standalone UI Version
# ===================================
FROM alpine:latest AS standalone-ui

# Install required container dependencies
RUN apk --update --no-cache add \
    bash curl wget whois tzdata jq ca-certificates htop fail2ban geoip openssh-client \
    && adduser -D -u 1000 -G root fail2ban

RUN mkdir -p /app /config /config/.ssh \
    /etc/fail2ban/jail.d \
    /etc/fail2ban/filter.d \
    /etc/fail2ban/action.d \
    /var/run/fail2ban \
    /usr/share/GeoIP \
    && touch /etc/fail2ban/jail.local \
    && chown -R fail2ban:0 /app /config /etc/fail2ban /var/run/fail2ban

# Set working directory
WORKDIR /config

# Copy Fail2Ban UI binary and templates from the build stage
COPY --from=builder /app/fail2ban-ui /app/fail2ban-ui
RUN chown fail2ban:0 /app/fail2ban-ui && chmod +x /app/fail2ban-ui
COPY --from=builder /app/pkg/web/templates /app/templates
COPY --from=builder /app/internal/locales /app/locales
# Copy static files (Tailwind CSS) if they exist
COPY --from=builder /app/pkg/web/static /app/static

# Set environment variables
ENV CONTAINER=true

# Persist config data
VOLUME ["/config"]

# Expose UI port (default: 8080, can be changed via PORT environment variable)
EXPOSE 8080

# Run the application as non-root (currently not possible because of fail2ban running as privileged)
#USER fail2ban

# Start Fail2Ban UI
CMD ["/app/fail2ban-ui"]
