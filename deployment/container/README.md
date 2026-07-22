# Container deployment

This guide covers building and running Fail2Ban UI with Podman or Docker.

## Quick start

### Pull the image

From Docker Hub (default):

```bash
podman pull swissmakers/fail2ban-ui:latest
# or with Docker:
docker pull swissmakers/fail2ban-ui:latest
```

From the Swissmakers registry (fallback):

```bash
podman pull registry.swissmakers.ch/infra/fail2ban-ui:latest
# or with Docker:
docker pull registry.swissmakers.ch/infra/fail2ban-ui:latest
```

### Run the container

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

The web interface is available at `http://localhost:8080`, or at your configured port.

## Building the image

### Prerequisites

- Docker or Podman
- Git

### Procedure

1. Clone the repository:
  ```bash
   git clone https://github.com/swissmakers/fail2ban-ui.git
   cd fail2ban-ui
  ```
2. Build the image:
  ```bash
   podman build -t fail2ban-ui:dev .
   # or
   docker build -t fail2ban-ui:dev .
  ```
   **Note:** The Dockerfile uses a multi-stage build with two stages, `builder` compiles the Go binary, `standalone-ui` is the final runtime image.
3. Verify the build:
  ```bash
   podman images fail2ban-ui
  ```

Build options:

```bash
# Build with a specific tag
podman build -t fail2ban-ui:v1.0.0 .

# Build without cache
podman build --no-cache -t fail2ban-ui:dev .
```

## Running the container

### Basic run command (local Fail2Ban instance)

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

### Custom port

Change the default port (8080) with the `PORT` environment variable:

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

The web interface is then available at `http://localhost:8436`.

### Container management

```bash
podman start fail2ban-ui          # start
podman stop fail2ban-ui           # stop
podman logs -f fail2ban-ui        # follow logs
podman exec -it fail2ban-ui /bin/bash   # shell inside the container

# remove:
podman stop fail2ban-ui
podman rm fail2ban-ui
```

## Volume mounts


| Volume              | Required             | Access     | SELinux flag | Purpose                                          |
| ------------------- | -------------------- | ---------- | ------------ | ------------------------------------------------ |
| `/config`           | yes                  | read/write | `:Z`         | SQLite database, settings, SSH keys              |
| `/etc/fail2ban`     | local connector only | read/write | `:Z`         | Fail2Ban configuration files                     |
| `/var/run/fail2ban` | local connector only | read/write | - (tmpfs)    | Fail2Ban control socket                          |
| `/var/log`          | local connector only | read-only  | `:ro`        | System logs for automated log path tests         |
| GeoIP directory     | optional             | read-only  | `:ro`        | MaxMind databases, only for the MaxMind provider |


Details:

### `/config` - configuration and database storage

- Host path: `/opt/podman-fail2ban-ui`, or any preferred location.
- Stores the SQLite database (`fail2ban-ui.db`) with server configurations and ban events, application settings, and the `.ssh/` directory with the keys used for remote server connections.
- On SELinux-enabled systems, mount with the `:Z` flag.

### `/etc/fail2ban` - Fail2Ban configuration

- Required only when managing a local Fail2Ban instance.
- Read/write access is required for configuration management.
- On SELinux-enabled systems, mount with the `:Z` flag.

### `/var/run/fail2ban` - Fail2Ban socket directory

- Required only for the local connector; provides access to the control socket `fail2ban.sock`.
- No SELinux flag is needed (tmpfs).

### `/var/log` - log files

- Required only for the local connector; mounted read-only (`:ro`).
- Used for the automatic log path tests when jails are enabled. If a test fails, the jail is auto-disabled to prevent Fail2Ban daemon errors.

### GeoIP database (optional)

- Mount the directory containing `GeoLite2-Country.mmdb` read-only, for example to `/usr/share/GeoIP`. The container path must match the path configured in the UI.
- Only needed for the MaxMind provider. By default, Fail2Ban UI uses the built-in ip-api.com provider, which requires no local database.

## Configuration

### Environment variables


| Variable       | Default   | Description                                                                                                                                                |
| -------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`         | `8080`    | Port of the web interface                                                                                                                                  |
| `BIND_ADDRESS` | `0.0.0.0` | Listen address. With host networking, set a specific IP, for example `127.0.0.1` or an internal interface IP, to keep the web UI off unprotected networks. |
| `CONTAINER`    | `true`    | Set automatically by the container; do not override                                                                                                        |


For the full list, including `CALLBACK_URL`, `CALLBACK_SECRET`, `BASE_PATH`, and OIDC, see [docs/configuration.md](../../docs/configuration.md).

### First launch

1. **Open the web interface** at `http://localhost:8080` (or your configured port).
2. **Add your first server** under **Settings -> Manage Servers**:
  - Local server: enable the local connector if Fail2Ban runs on the same host.
  - Remote server: add a server over SSH or through an API agent.
3. **Configure the settings**
  - **Fail2Ban Callback URL**: the URL every Fail2Ban instance uses to send ban alerts back to the UI.
    - Local deployments: use the same port as Fail2Ban UI, for example `http://127.0.0.1:8080`.
    - Reverse proxy setups: use the TLS-terminated endpoint, for example `https://fail2ban.example.com`.
    - The callback URL updates automatically when you change the server port, as long as the default localhost pattern is in use.
  - **Callback URL Secret**: an auto-generated 42-character secret that authenticates ban notification requests, viewable in the settings with a show/hide toggle.
  - **GeoIP Provider**: MaxMind (local database) or Built-in (ip-api.com). The default is Built-in.
  - **Maximum Log Lines**: how many log lines to include in ban notifications (default: 50).
  - Email alerts, alert countries, language preferences, and the security settings as needed.

**Note:** A local Fail2Ban service is optional. Fail2Ban UI can manage remote Fail2Ban servers over SSH or API agents without a local Fail2Ban installation in the container.

**Important:** The callback URL must be reachable from every Fail2Ban instance, local and remote, that sends alerts. If you change the UI port, update the callback URL accordingly.

## Compose

For easier management, use a Compose file:

```yaml
services:
  fail2ban-ui:
    # Pre-built image from Docker Hub (default)
    image: swissmakers/fail2ban-ui:latest

    # Alternative: Swissmakers registry (fallback)
    # image: registry.swissmakers.ch/infra/fail2ban-ui:latest

    # Or build from source:
    # build:
    #   context: .
    #   dockerfile: Dockerfile

    container_name: fail2ban-ui
    # privileged: true  # needed only for a container-local Fail2Ban instance
    #                   # (fail2ban.sock is owned by root); see the all-in-one example
    network_mode: host

    environment:
      # Port of the web interface (default: 8080)
      - PORT=8080

    volumes:
      # Required: SQLite database, application settings, and SSH keys
      - /opt/podman-fail2ban-ui:/config:Z
      # Required: validates log paths before enabling jails
      - /var/log:/var/log:ro

      # Required for a local Fail2Ban instance: configuration directory
      - /etc/fail2ban:/etc/fail2ban:Z
      # Required for a local Fail2Ban instance: control socket
      - /var/run/fail2ban:/var/run/fail2ban

      # Optional: MaxMind GeoIP databases (MaxMind provider only)
      #- /usr/share/GeoIP:/usr/share/GeoIP:ro

    restart: unless-stopped
```

```bash
docker-compose up -d      # start
docker-compose logs -f    # follow logs
docker-compose down       # stop
```

### All-in-one setup (Fail2Ban + Fail2Ban UI)

For a fully containerized setup with both Fail2Ban and Fail2Ban UI, use the all-in-one Compose example:

```bash
# Copy the example from the project root
cp ../docker-compose-allinone.example.yml docker-compose.yml

# Adjust in docker-compose.yml:
# - PORT for the UI
# - timezone (TZ)
# - volume paths

docker-compose up -d
```

Characteristics:

- Fail2Ban (linuxserver/fail2ban) and Fail2Ban UI in a single Compose file
- Both containers share the same Fail2Ban configuration directory and control socket
- `network_mode: host` for proper iptables integration

Volume structure:

```
./fail2ban-config/fail2ban  -> /config/fail2ban (fail2ban container)
./fail2ban-config/fail2ban  -> /etc/fail2ban (fail2ban-ui container)
./f2b-run                   -> /var/run/fail2ban (both containers)
./config                    -> /config (fail2ban-ui container)
```

**Important:**

- The fail2ban-ui container requires `privileged: true` in this setup to modify Fail2Ban configs owned by root.
- Both containers must use `network_mode: host`.
- Ensure the SELinux labels are correct (`:z` or `:Z` flags).

See `docker-compose-allinone.example.yml` in the project root for the complete configuration.

## Fail2Ban banaction configuration

### nftables vs. iptables

Modern distributions - Rocky Linux 9+, RHEL 9+, Fedora 36+, Debian 12+ - use **nftables** as the default firewall backend. When Fail2Ban is configured with `iptables-multiport` or `iptables-allports`, it may fail with errors such as:

- `Extension multiport revision 0 not supported, missing kernel module?`
- `iptables v1.8.11 (nf_tables): RULE_INSERT failed (No such file or directory)`

Solution - switch Fail2Ban to nftables-based actions:

1. Open the Fail2Ban UI web interface.
2. Go to **Settings -> Fail2Ban Settings**.
3. Change **Banaction** from `iptables-multiport` to `nftables-multiport`.
4. Change **Banaction Allports** from `iptables-allports` to `nftables-allports`.
5. Save; Fail2Ban reloads automatically.

### firewalld (RHEL, Rocky Linux)

For systems managed by `firewalld`, use:

- **Banaction**: `firewallcmd-rich-rules`
- **Banaction Allports**: `firewallcmd-allports`

Alternatively, since firewalld uses the nftables backend by default on RHEL 9+, the `nftables-multiport` / `nftables-allports` actions also work.

Verify the firewall backend:

```bash
# nftables backend in use?
iptables --version
# "iptables v1.8.11 (nf_tables)" indicates the nftables backend

# firewalld active?
systemctl status firewalld
```

## SELinux configuration

With SELinux enabled, the optional modules below may be needed so the **container** can talk to the host Fail2Ban socket and read the expected logs.

**Note:** This is separate from the **host** Fail2Ban calling back to the UI with `curl`. For denials on `fail2ban_t` connecting to HTTP/HTTPS ports, see [docs/security.md](../../docs/security.md#selinux) - typically solved with `setsebool -P nis_enabled 1` on RHEL-family systems.

### Apply the pre-built policies

The policies are located in `./SELinux/`:

```bash
cd deployment/container/SELinux
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

### Compile and install the policies manually

To modify or rebuild the SELinux rules:

```bash
cd deployment/container/SELinux

# Compile the module
checkmodule -M -m -o fail2ban-container-client.mod fail2ban-container-client.te

# Package the module
semodule_package -o fail2ban-container-client.pp -m fail2ban-container-client.mod

# Install the module
semodule -i fail2ban-container-client.pp
```

### Verification

```bash
semodule -l | grep fail2ban
```

Expected output:

- `fail2ban-container-ui`
- `fail2ban-container-client`

## Troubleshooting

### Fail2Ban cannot ban IPs (nftables/firewalld issues)

If Fail2Ban fails to ban IPs with errors related to iptables or multiport extensions, see [Fail2Ban banaction configuration](#fail2ban-banaction-configuration) above.

### UI not accessible

1. Check whether the container is running:
  ```bash
   podman ps | grep fail2ban-ui
  ```
2. Check the container logs:
  ```bash
   podman logs fail2ban-ui
  ```
3. Verify the port is not blocked by the firewall:
  ```bash
   sudo firewall-cmd --list-ports
   sudo firewall-cmd --add-port=8080/tcp --permanent
   sudo firewall-cmd --reload
  ```
4. Check whether the process is running inside the container:
  ```bash
   podman exec -it fail2ban-ui ps aux | grep fail2ban-ui
  ```
5. Verify the port configuration: check the `PORT` environment variable and the container logs for the actual listening port.

### No servers configured

Symptoms: empty dashboard, no servers visible.

1. Go to **Settings -> Manage Servers** in the web UI.
2. Enable the **Local Connector** if Fail2Ban runs locally.
3. Add a remote server over SSH or an API agent.
4. Verify the server connection status.

### SSH connection issues

1. Verify that SSH key authentication works from the host:
  ```bash
   ssh -i /opt/podman-fail2ban-ui/.ssh/your_key user@remote-host
  ```
2. Verify the SSH user's permissions on the remote server:
  - sudo access for `fail2ban-client` and `systemctl restart fail2ban` (via sudoers)
  - filesystem ACLs on `/etc/fail2ban` for configuration file access
  - see [docs/security.md](../../docs/security.md#ssh-connector-hardening) for the recommended service-account setup
3. Check the key location: SSH keys belong in `/config/.ssh` inside the container, with permissions `600`.
4. Enable debug mode under **Settings** for detailed error messages.
5. Verify network connectivity: the container needs network access to the remote SSH servers. Check whether `--network=host` is in use, or configure the appropriate port mappings.

### Permission denied errors

1. Check the SELinux context on the volumes:
  ```bash
   ls -Z /opt/podman-fail2ban-ui
   ls -Z /etc/fail2ban
  ```
2. Apply the correct context if needed:
  ```bash
   chcon -Rt container_file_t /opt/podman-fail2ban-ui
  ```
3. Verify the mount flags: `:Z` for read/write volumes on SELinux systems, `:ro` for read-only volumes.

### Database errors

1. Check the database file permissions:
  ```bash
   ls -la /opt/podman-fail2ban-ui/fail2ban-ui.db
  ```
2. Verify the database integrity:
  ```bash
   podman exec -it fail2ban-ui sqlite3 /config/fail2ban-ui.db "PRAGMA integrity_check;"
  ```
3. Back up before any recovery attempt:
  ```bash
   cp /opt/podman-fail2ban-ui/fail2ban-ui.db /opt/podman-fail2ban-ui/fail2ban-ui.db.backup
  ```

## Contact and support

- Issues, contributions, and feature requests: [GitHub Issues](https://github.com/swissmakers/fail2ban-ui/issues)
- Enterprise support: [Swissmakers GmbH](https://swissmakers.ch)

