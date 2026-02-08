#!/usr/bin/env bash
# cleanup_dev.sh -- Reset the OIDC dev environment to a clean state.
# This stops and removes all containers, networks, and volumes defined in
# container-compose.yml, then deletes the generated data directories so you
# can start fresh with "podman compose up -d" (or docker compose).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/container-compose.yml"

# colour helpers
if [ -t 1 ]; then
  BOLD='\033[1m' RESET='\033[0m' GREEN='\033[0;32m' YELLOW='\033[0;33m'
else
  BOLD='' RESET='' GREEN='' YELLOW=''
fi
info()  { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }

# detect compose command
if command -v podman &>/dev/null && podman compose version &>/dev/null 2>&1; then
  COMPOSE="podman compose"
elif command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  warn "Neither 'podman compose' nor 'docker compose' found."
  warn "Skipping container teardown - only data directories will be removed."
  COMPOSE=""
fi

# stop and remove containers / networks
if [ -n "$COMPOSE" ] && [ -f "$COMPOSE_FILE" ]; then
  info "Stopping and removing containers defined in container-compose.yml …"
  $COMPOSE -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
else
  warn "Compose file not found at ${COMPOSE_FILE} - skipping container teardown."
fi

# remove generated data directories
# These match the volume mounts and the .gitignore entries
DATA_DIRS=(
  config
  f2b-run-local
  fail2ban-config-local
  keycloak-data
  keycloak-db
  pocket-id-data
  authentik-media
  authentik-db
  authelia-config
  authelia-db
  authelia-redis
)

info "Removing generated data directories …"
for dir in "${DATA_DIRS[@]}"; do
  target="${SCRIPT_DIR}/${dir}"
  if [ -e "$target" ]; then
    rm -rf "$target"
    info "  Removed ${dir}/"
  fi
done

# remove generated .env
if [ -f "${SCRIPT_DIR}/.env" ]; then
  rm -f "${SCRIPT_DIR}/.env"
  info "  Removed .env"
fi

echo ""
info "${BOLD}OIDC dev environment cleaned.${RESET} Run 'podman compose up -d' (or docker compose) to start fresh."
