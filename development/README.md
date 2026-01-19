# Development Environment

This directory contains Docker Compose configurations for local development and testing of Fail2ban UI.

## Available Development Setups

### 1. OIDC Authentication Testing (`oidc/`)

Complete OIDC authentication setup with Keycloak and Pocket-ID for testing authentication flows.

**See:** [oidc/README.md](./oidc/README.md)

### 2. SSH and Local Fail2ban Testing (`ssh_and_local/`)

Setup for testing Fail2ban UI with:
- Local Fail2ban instance (container)
- Remote Fail2ban instance via SSH (container)

**See:** [ssh_and_local/README.md](./ssh_and_local/README.md)

## Quick Start

1. **Build the fail2ban-ui development image:**
   ```bash
   podman build -t localhost/fail2ban-ui:dev .
   # or
   docker build -t localhost/fail2ban-ui:dev .
   ```

2. **Choose a development setup:**
   - For OIDC testing: `cd oidc/`
   - For SSH/Local testing: `cd ssh_and_local/`

3. **Start the services:**
   ```bash
   podman compose up -d
   # or
   docker-compose up -d
   ```

4. **Access the services:**
   - Fail2ban UI: `http://localhost:3080` (or configured port)
   - OIDC Provider (Pocket-ID): `http://localhost:3000` (if using OIDC setup)

## Notes

- All development containers use the `DEV_` prefix for easy identification
- Data volumes are stored in subdirectories (e.g., `./config`, `./pocket-id-data`)
- These setups are for **development only** - not for production use
- Some containers require `privileged: true` or specific capabilities for full functionality
