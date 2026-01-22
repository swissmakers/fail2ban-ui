# Fail2Ban UI Container Deployment Guide

A comprehensive guide for building and deploying Fail2Ban UI using containers (Docker/Podman).

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Container Image](#building-the-container-image)
- [Running the Container](#running-the-container)
- [Volume Mounts](#volume-mounts)
- [Configuration](#configuration)
- [Docker Compose](#docker-compose)
- [Fail2Ban Banaction Configuration](#fail2ban-banaction-configuration)
- [SELinux Configuration](#selinux-configuration)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Using Pre-built Image

**Pull the official image with podman from Docker Hub (default):**
```bash
podman pull swissmakers/fail2ban-ui:latest
# or with Docker:
docker pull swissmakers/fail2ban-ui:latest
```

**Alternative: Pull from Swissmakers registry (fallback):**
```bash
podman pull registry.swissmakers.ch/infra/fail2ban-ui:latest
# or with Docker:
docker pull registry.swissmakers.ch/infra/fail2ban-ui:latest
```

**Run the container:**
```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  swissmakers/fail2ban-ui:latest
```

Access the web interface at `http://localhost:8080` (or your configured port).

---

## Building the Container Image

### Prerequisites

- Docker or Podman installed
- Git (to clone the repository)

### Build Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/swissmakers/fail2ban-ui.git
   cd fail2ban-ui
   ```

2. **Build the image:**
   ```bash
   # Using Podman
   podman build -t fail2ban-ui:dev .
   
   # Using Docker
   docker build -t fail2ban-ui:dev .
   ```

   > **Note:** The Dockerfile uses a multi-stage build with two stages: `builder` (compiles the Go binary) and `standalone-ui` (final runtime image).

3. **Verify the build:**
   ```bash
   podman images fail2ban-ui
   # or
   docker images fail2ban-ui
   ```

### Build Options

You can customize the build with additional flags:

```bash
# Build with a specific tag
podman build -t fail2ban-ui:v1.0.0 .

# Build without cache
podman build --no-cache -t fail2ban-ui:dev .
```

---

## Running the Container

### Basic Run Command (for a local fail2ban connection)

```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  fail2ban-ui:latest
```

### Custom Port Configuration

You can change the default port (8080) using the `PORT` environment variable:

```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -e PORT=8436 \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  fail2ban-ui:latest
```

Access the web interface at `http://localhost:8436`.

### Container Management

**Start the container:**
```bash
podman start fail2ban-ui
```

**Stop the container:**
```bash
podman stop fail2ban-ui
```

**View logs:**
```bash
podman logs -f fail2ban-ui
```

**Remove the container:**
```bash
podman stop fail2ban-ui
podman rm fail2ban-ui
```

**Execute commands inside the container:**
```bash
podman exec -it fail2ban-ui /bin/bash
```

---

## Volume Mounts

The Fail2Ban UI container requires several volume mounts to function properly. Below is a detailed explanation of each volume:

### Required Volumes

#### `/config` - Configuration and Database Storage
- **Host Path:** `/opt/podman-fail2ban-ui` (or your preferred location)
- **Container Path:** `/config`
- **Purpose:** Stores the SQLite database (`fail2ban-ui.db`), application settings, and SSH keys for remote server connections
- **Permissions:** Read/Write
- **SELinux Context:** `:Z` flag required on SELinux-enabled systems
- **Contents:**
  - `fail2ban-ui.db` - SQLite database with server configurations and ban events
  - `.ssh/` - Directory for SSH keys used for remote server connections
  - Application configuration files

#### `/etc/fail2ban` - Fail2Ban Configuration Directory (reqired for local fail2ban connector only)
- **Host Path:** `/etc/fail2ban`
- **Container Path:** `/etc/fail2ban`
- **Purpose:** Access to Fail2Ban configuration files (jails, filters, actions)
- **Permissions:** Read/Write (required for configuration management)
- **SELinux Context:** `:Z` flag required on SELinux-enabled systems
- **Note:** Required if managing local Fail2Ban instance

#### `/var/run/fail2ban` - Fail2Ban Socket Directory (reqired for local fail2ban connector only)
- **Host Path:** `/var/run/fail2ban`
- **Container Path:** `/var/run/fail2ban`
- **Purpose:** Access to Fail2Ban control socket (`fail2ban.sock`)
- **Permissions:** Read/Write
- **SELinux Context:** Not required (tmpfs)
- **Note:** Required for local Fail2Ban management

#### `/var/log` - Log Files (reqired for local fail2ban connector only)
- **Host Path:** `/var/log`
- **Container Path:** `/var/log`
- **Purpose:** Read access to system logs for automatically logpath-tests on jail enabe
- **Permissions:** Read-Only (`:ro`)
- **Note:** If test fails, jail is auto-disabled to prevent fail2ban daemon errors

### Optional Volumes

#### GeoLite2-Country.mmdb - GeoIP Database
- **Host Path:** `/path/to/your/GeoIPFolder`
- **Container Path:** e.g. `/usr/share/GeoIP` paht must match the settings in the UI.
- **Purpose:** Only needed if you want to use the MaxMind provider.
- **Permissions:** Read-Only (`:ro`)
- **Note:** Fail2Ban UI uses the built-in ip-api.com by default, which requires no local database

### Volume Summary Table

| Volume | Required | Read/Write | SELinux Context | Purpose |
|--------|----------|------------|-----------------|---------|
| `/config` | ✅ Yes | Read/Write | `:Z` | Database, settings, SSH keys |
| `/etc/fail2ban` | ✅ Yes* | Read/Write | `:Z` | Fail2Ban configuration files |
| `/var/run/fail2ban` | ✅ Yes* | Read/Write | - | Fail2Ban control socket |
| `/var/log` | ✅ Yes* | Read-Only | `:ro` | System log files for automated logpath tests on jail management. |
| `/path/to/your/GeoIPFolder` | ⚠️ Optional | Read-Only | `:ro` | MaxMind GeoIP databases (only needed if using MaxMind provider) |

*Required only if managing a local Fail2Ban instance. Not needed for remote-only deployments.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Port number for the web interface |
| `BIND_ADDRESS` | `0.0.0.0` | IP address to bind the web interface to. Useful when running with host networking to prevent exposing the web UI to unprotected networks. Set to a specific IP (e.g., `127.0.0.1` or a specific interface IP) to restrict access. |
| `CONTAINER` | `true` | Automatically set by the container (do not override) |

### First Launch Configuration

After starting the container, access the web interface and configure your first Fail2Ban server:

1. **Access the Web Interface**
   - Navigate to `http://localhost:8080` (or your configured port)

2. **Add Your First Server**
   - Go to **Settings** → **Manage Servers**
   - **Local Server**: Enable the local connector if Fail2Ban runs on the same host
   - **Remote Server**: Add via SSH or API agent connection

3. **Configure Settings**
   - **Fail2Ban Callback URL**: This URL is used by all Fail2Ban instances to send ban alerts back to Fail2Ban UI
     - For local deployments: Use the same port as Fail2Ban UI (e.g., `http://127.0.0.1:8080` or your configured port)
     - For reverse proxy setups: Use your TLS-encrypted endpoint (e.g., `https://fail2ban.example.com`)
     - The callback URL automatically updates when you change the server port (if using the default localhost pattern)
   - **Callback URL Secret**: Auto-generated 42-character secret for authenticating ban notification requests (viewable in Settings with show/hide toggle)
   - **GeoIP Provider**: Choose between MaxMind (local database) or Built-in (ip-api.com) - default is Built-in
   - **Maximum Log Lines**: Configure how many log lines to include in ban notifications (default: 50)
   - Set up email alerts (optional)
   - Configure language preferences
   - Adjust security settings

> **Note:** The local Fail2Ban service is optional. Fail2Ban UI can manage remote Fail2Ban servers via SSH or API agents without requiring a local Fail2Ban installation in the container.

> **Important:** The Fail2Ban Callback URL must be accessible from all Fail2Ban instances (local and remote) that need to send alerts. If you change the Fail2Ban UI port, ensure the callback URL is updated accordingly.

---

## Docker Compose

For easier management, you can use Docker Compose. Create a `docker-compose.yml` file:

```yaml
services:
  fail2ban-ui:
    # Use pre-built image from Docker Hub (default)
    image: swissmakers/fail2ban-ui:latest

    # Alternative: Use Swissmakers registry (fallback)
    # image: registry.swissmakers.ch/infra/fail2ban-ui:latest

    # Or build from source (uncomment to use):
    # build:
    #   context: .
    #   dockerfile: Dockerfile

    container_name: fail2ban-ui
    #privileged: true # needed if you want to use a container-local fail2ban instance (because fail2ban.sock is owned by root)
    # a single all-in-one container is planned, currently you need to use the fail2ban container from linuxserver, see docker-compose-allinone.yml for an example
    network_mode: host

    environment:
      # Change this to use a different port for the web interface (defaults is 8080)
      - PORT=8080

    volumes:
      # Required for fail2ban-ui: Stores SQLite database, application settings, and SSH keys of the fail2ban-ui container
      - /opt/podman-fail2ban-ui:/config:Z
      # Required for fail2ban-ui: Used for testing, that logpath is working, before enabeling a jail. Without this read only access the fail2ban-ui will not be able to enable jails (logpath-test would fail)
      - /var/log:/var/log:ro

      # Required for local fail2ban instance: Fail2Ban configuration directory, needed for managing a local Fail2Ban instance (e.g. on host system) via fail2ban-ui
      - /etc/fail2ban:/etc/fail2ban:Z
      # Required for local fail2ban instance: Fail2Ban socket directory, needed for local Fail2Ban (e.g. on host system) for control via fail2ban-ui
      - /var/run/fail2ban:/var/run/fail2ban

      # Optional: Map MaxMind GeoIP databases (only needed if using MaxMind provider)
      #- /usr/share/GeoIP:/usr/share/GeoIP:ro

    restart: unless-stopped
```

**Start with Docker Compose:**
```bash
docker-compose up -d
```

**View logs:**
```bash
docker-compose logs -f
```

**Stop:**
```bash
docker-compose down
```

### All-in-One Docker Compose Setup

For a complete containerized setup with both Fail2Ban and Fail2Ban UI, use the all-in-one Docker Compose configuration:

```bash
# Copy the all-in-one example file
cp ../docker-compose-allinone.example.yml docker-compose.yml

# Edit docker-compose.yml to customize:
# - PORT environment variable for Fail2Ban UI
# - Timezone (TZ environment variable)
# - Volume paths

# Start both services
docker-compose up -d
```

**Features:**
- **Combined Setup**: Fail2Ban (linuxserver/fail2ban) and Fail2Ban UI in one compose file
- **Shared Configuration**: Both containers share the same Fail2Ban configuration directory
- **Shared Socket**: Both containers access the same Fail2Ban control socket
- **Network Mode**: Uses `host` network mode for proper iptables integration

**Volume Structure:**
```
./fail2ban-config/fail2ban  → /config/fail2ban (fail2ban container)
./fail2ban-config/fail2ban  → /etc/fail2ban (fail2ban-ui container)
./f2b-run                   → /var/run/fail2ban (both containers)
./config                    → /config (fail2ban-ui container)
```

**Important Notes:**
- The fail2ban-ui container requires `privileged: true` to modify Fail2Ban configs owned by root
- Both containers must use `network_mode: host` for proper networking
- Ensure SELinux labels are correct (`:z` or `:Z` flags)

See `docker-compose-allinone.example.yml` in the project root for the complete configuration.

---

## Fail2Ban Banaction Configuration

### nftables vs iptables

Modern Linux distributions (Rocky Linux 9+, RHEL 9+, Fedora 36+, Debian 12+) use **nftables** as the default firewall backend instead of legacy iptables. When Fail2Ban is configured to use `iptables-multiport` or `iptables-allports`, it may fail with errors like:

- `Extension multiport revision 0 not supported, missing kernel module?`
- `iptables v1.8.11 (nf_tables): RULE_INSERT failed (No such file or directory)`

**Solution:** Configure Fail2Ban to use nftables-based actions:

1. Access the Fail2Ban UI web interface
2. Navigate to **Settings** → **Fail2Ban Settings**
3. Change **Banaction** from `iptables-multiport` to `nftables-multiport`
4. Change **Banaction Allports** from `iptables-allports` to `nftables-allports`
5. Save settings (Fail2Ban will automatically reload)

### firewalld (Rocky Linux / Red Hat)

For systems using `firewalld` as the firewall management tool (common on Rocky Linux and Red Hat Enterprise Linux), you can use:

- **Banaction**: `firewallcmd-rich-rules`
- **Banaction Allports**: `firewallcmd-allports`

Alternatively, if firewalld is configured to use the nftables backend (default in RHEL 9+), you can use `nftables-multiport` / `nftables-allports` as described above.

**Verify your system's firewall backend:**
```bash
# Check if using nftables
iptables --version
# Output: iptables v1.8.11 (nf_tables) indicates nftables backend

# Check if firewalld is active
systemctl status firewalld
```

---

## SELinux Configuration

If SELinux is enabled on your system, you must apply the required SELinux policies to allow the container to communicate with Fail2Ban.

### Apply Pre-built Policies

The policies are located in `./SELinux/`:

```bash
cd deployment/container/SELinux
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

### Manually Compile and Install Policies

If you want to modify or compile the SELinux rules yourself:

```bash
cd deployment/container/SELinux

# Compile the module
checkmodule -M -m -o fail2ban-container-client.mod fail2ban-container-client.te

# Package the module
semodule_package -o fail2ban-container-client.pp -m fail2ban-container-client.mod

# Install the module
semodule -i fail2ban-container-client.pp
```

### Verify SELinux Policies

```bash
semodule -l | grep fail2ban
```

You should see:
- `fail2ban-container-ui`
- `fail2ban-container-client`

---

## Troubleshooting

### Fail2Ban Cannot Ban IPs (nftables/firewalld Issues)

If Fail2Ban fails to ban IPs with errors related to iptables or multiport extensions, see the [Fail2Ban Banaction Configuration](#fail2ban-banaction-configuration) section above for detailed solutions.

### UI Not Accessible

**Symptoms:** Cannot access web interface

**Solutions:**
1. **Check if container is running:**
   ```bash
   podman ps | grep fail2ban-ui
   ```

2. **Check container logs:**
   ```bash
   podman logs fail2ban-ui
   ```

3. **Verify port is not blocked by firewall:**
   ```bash
   sudo firewall-cmd --list-ports
   sudo firewall-cmd --add-port=8080/tcp --permanent
   sudo firewall-cmd --reload
   ```

4. **Check if Fail2Ban UI process is running inside container:**
   ```bash
   podman exec -it fail2ban-ui ps aux | grep fail2ban-ui
   ```

5. **Verify port configuration:**
   - Check if `PORT` environment variable is set correctly
   - Check container logs for the actual port being used

### No Servers Configured

**Symptoms:** Empty dashboard, no servers visible

**Solutions:**
1. Navigate to **Settings** → **Manage Servers** in the web UI
2. Enable **Local Connector** (if Fail2Ban runs locally)
3. Add remote server via SSH or API agent
4. Verify server connection status

### SSH Connection Issues

**Symptoms:** Cannot connect to remote server

**Solutions:**
1. **Verify SSH key authentication works from the host:**
   ```bash
   ssh -i /opt/podman-fail2ban-ui/.ssh/your_key user@remote-host
   ```

2. **Ensure SSH user has proper permissions on remote server:**
   - Sudo access for `fail2ban-client` and `systemctl restart fail2ban` (configured via sudoers)
   - File system ACLs on `/etc/fail2ban` for configuration file access
   - See the main README for recommended setup with service account and ACLs

3. **Check SSH keys location:**
   - SSH keys should be placed in `/config/.ssh` directory inside the container
   - Verify key permissions (should be 600)

4. **Enable debug mode:**
   - Go to **Settings** → Enable debug mode for detailed error messages

5. **Verify network connectivity:**
   - The container needs network access to remote SSH servers
   - Check if using `--network=host` or configure proper port mappings

### Permission Denied Errors

**Symptoms:** Permission errors when accessing Fail2Ban files

**Solutions:**
1. **Check SELinux context on volumes:**
   ```bash
   ls -Z /opt/podman-fail2ban-ui
   ls -Z /etc/fail2ban
   ```

2. **Apply correct SELinux context:**
   ```bash
   chcon -Rt container_file_t /opt/podman-fail2ban-ui
   ```

3. **Verify volume mount flags:**
   - Use `:Z` flag for read/write volumes on SELinux systems
   - Use `:ro` flag for read-only volumes

### Database Errors

**Symptoms:** Database-related errors in logs

**Solutions:**
1. **Check database file permissions:**
   ```bash
   ls -la /opt/podman-fail2ban-ui/fail2ban-ui.db
   ```

2. **Verify database integrity:**
   ```bash
   podman exec -it fail2ban-ui sqlite3 /config/fail2ban-ui.db "PRAGMA integrity_check;"
   ```

3. **Backup and recreate if corrupted:**
   ```bash
   cp /opt/podman-fail2ban-ui/fail2ban-ui.db /opt/podman-fail2ban-ui/fail2ban-ui.db.backup
   ```

---

## Contact & Support

For issues, contributions, or feature requests, visit our GitHub repository:  
🔗 [GitHub Issues](https://github.com/swissmakers/fail2ban-ui/issues)

For enterprise support, visit:  
🔗 [Swissmakers GmbH](https://swissmakers.ch)
