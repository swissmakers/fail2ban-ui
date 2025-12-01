# Fail2Ban UI Container Deployment Guide

A comprehensive guide for building and deploying Fail2Ban UI using containers (Docker/Podman).

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Container Image](#building-the-container-image)
- [Running the Container](#running-the-container)
- [Volume Mounts](#volume-mounts)
- [Configuration](#configuration)
- [Docker Compose](#docker-compose)
- [SELinux Configuration](#selinux-configuration)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Using Pre-built Image

**Pull the official image:**
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
  -v /usr/share/GeoIP:/usr/share/GeoIP:ro \
  registry.swissmakers.ch/infra/fail2ban-ui:latest
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
   podman build -t fail2ban-ui:latest .
   
   # Using Docker
   docker build -t fail2ban-ui:latest .
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
podman build --no-cache -t fail2ban-ui:latest .
```

---

## Running the Container

### Basic Run Command

```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /usr/share/GeoIP:/usr/share/GeoIP:ro \
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
  -v /usr/share/GeoIP:/usr/share/GeoIP:ro \
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

#### `/etc/fail2ban` - Fail2Ban Configuration Directory
- **Host Path:** `/etc/fail2ban`
- **Container Path:** `/etc/fail2ban`
- **Purpose:** Access to Fail2Ban configuration files (jails, filters, actions)
- **Permissions:** Read/Write (required for configuration management)
- **SELinux Context:** `:Z` flag required on SELinux-enabled systems
- **Note:** Required if managing local Fail2Ban instance

#### `/var/run/fail2ban` - Fail2Ban Socket Directory
- **Host Path:** `/var/run/fail2ban`
- **Container Path:** `/var/run/fail2ban`
- **Purpose:** Access to Fail2Ban control socket (`fail2ban.sock`)
- **Permissions:** Read/Write
- **SELinux Context:** Not required (tmpfs)
- **Note:** Required for local Fail2Ban management

### Optional Volumes

#### `/var/log` - System Log Files
- **Host Path:** `/var/log`
- **Container Path:** `/var/log`
- **Purpose:** Read access to system logs for filter testing and log analysis
- **Permissions:** Read-Only (`:ro`)
- **SELinux Context:** `:ro` flag prevents SELinux issues
- **Note:** Useful for testing Fail2Ban filters against log files

#### `/usr/share/GeoIP` - GeoIP Database Directory
- **Host Path:** `/usr/share/GeoIP`
- **Container Path:** `/usr/share/GeoIP`
- **Purpose:** Access to GeoIP databases for geographic threat analysis
- **Permissions:** Read-Only (`:ro`)
- **SELinux Context:** `:ro` flag prevents SELinux issues
- **Note:** Optional but recommended for geographic IP analysis features

### Volume Summary Table

| Volume | Required | Read/Write | SELinux Context | Purpose |
|--------|----------|------------|-----------------|---------|
| `/config` | ✅ Yes | Read/Write | `:Z` | Database, settings, SSH keys |
| `/etc/fail2ban` | ✅ Yes* | Read/Write | `:Z` | Fail2Ban configuration files |
| `/var/run/fail2ban` | ✅ Yes* | Read/Write | - | Fail2Ban control socket |
| `/var/log` | ⚠️ Optional | Read-Only | `:ro` | System log files |
| `/usr/share/GeoIP` | ⚠️ Optional | Read-Only | `:ro` | GeoIP databases |

*Required only if managing a local Fail2Ban instance. Not needed for remote-only deployments.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Port number for the web interface |
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
   - Set up email alerts (optional)
   - Configure language preferences
   - Adjust security settings

> **Note:** The local Fail2Ban service is optional. Fail2Ban UI can manage remote Fail2Ban servers via SSH or API agents without requiring a local Fail2Ban installation in the container.

> **Important:** The Fail2Ban Callback URL must be accessible from all Fail2Ban instances (local and remote) that need to send alerts. If you change the Fail2Ban UI port, ensure the callback URL is updated accordingly.

---

## Docker Compose

For easier management, you can use Docker Compose. Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  fail2ban-ui:
    image: registry.swissmakers.ch/infra/fail2ban-ui:latest
    # Or build from source:
    # build:
    #   context: .
    #   dockerfile: Dockerfile
    container_name: fail2ban-ui
    network_mode: host
    restart: unless-stopped
    environment:
      - PORT=8436  # Custom port (optional, defaults to 8080)
    volumes:
      # Required: Configuration and database storage
      - /opt/podman-fail2ban-ui:/config:Z
      # Required: Fail2Ban configuration directory
      - /etc/fail2ban:/etc/fail2ban:Z
      # Required: Fail2Ban socket directory
      - /var/run/fail2ban:/var/run/fail2ban
      # Optional: System logs (read-only)
      - /var/log:/var/log:ro
      # Optional: GeoIP databases (read-only)
      - /usr/share/GeoIP:/usr/share/GeoIP:ro
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
