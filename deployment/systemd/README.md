# systemd deployment

This guide describes two ways to run Fail2Ban UI as a systemd service:

1. A service that starts a locally compiled binary.
2. A service that starts the Fail2Ban UI container.

## SELinux-enabled systems (host Fail2Ban → UI callbacks)

Fail2Ban runs its ban and unban actions as `fail2ban_t`. The UI callback uses `curl` to POST to the configured URL, plain HTTP, HTTPS, or HTTPS behind a reverse proxy. On RHEL, Rocky Linux, AlmaLinux, and similar distributions with the targeted policy, SELinux often denies that outbound TCP connection until the corresponding network access is allowed.

Recommended fix, to be applied on **every** SELinux-enabled Fail2Ban host:

```bash
sudo setsebool -P nis_enabled 1
```

This uses a boolean already shipped by the distribution, which is preferable to maintaining a one-off `audit2allow` module. If your security team forbids the boolean, work with them on an approved exception (a custom policy). Do not disable SELinux entirely.

**Note:** A *containerized* Fail2Ban UI (Podman/Docker) talking to the host Fail2Ban socket and logs may additionally require the optional modules described in [deployment/container/README.md](../container/README.md#selinux-configuration). That is a separate concern.

## Option 1: Run the compiled binary

This option runs Fail2Ban UI from `/opt/fail2ban-ui/` under systemd.

### Prerequisites

Install Go 1.27 or later and the required dependencies:

```bash
sudo dnf install -y golang git jq
```

**Note:** A local Fail2Ban installation is optional. Fail2Ban UI can manage remote Fail2Ban servers over SSH or API agents without a local instance.

### Build

Clone the repository and build:

```bash
sudo git clone https://github.com/swissmakers/fail2ban-ui.git /opt/fail2ban-ui
cd /opt/fail2ban-ui
./build-tailwind.sh
sudo go build -o fail2ban-ui ./cmd/server/main.go
```

The web templates, translation JSON files, and `pkg/web/static` are embedded into the binary at compile time. Only the `fail2ban-ui` executable needs to be shipped, plus a writable `WorkingDirectory` for the SQLite database.

### Create the unit file

Save the following as `/etc/systemd/system/fail2ban-ui.service`. For production deployments, use a dedicated service account instead of root.

```ini
[Unit]
Description=Fail2Ban UI
After=network.target
Wants=fail2ban.service

[Service]
Type=simple
WorkingDirectory=/opt/fail2ban-ui
ExecStart=/opt/fail2ban-ui/fail2ban-ui
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

### Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable fail2ban-ui.service --now
sudo systemctl status fail2ban-ui.service
```

### Operate the service

```bash
sudo journalctl -u fail2ban-ui.service -f   # follow logs
sudo systemctl restart fail2ban-ui.service  # restart
sudo systemctl stop fail2ban-ui.service     # stop
```

### First launch and server configuration

After starting the service, open the web interface at `http://localhost:8080` (or your configured port).

**Important:** On first launch you must either enable the **local connector** (if Fail2Ban runs on the same host) or add a **remote server** over SSH. Go to **Settings → Manage Servers** to configure the first Fail2Ban server.

Then review the settings:

- **Fail2Ban Callback URL**: the URL Fail2Ban instances use to send ban alerts. It auto-updates with port changes when the default localhost pattern is in use.
- **Callback URL Secret**: an auto-generated 42-character secret for callback authentication, viewable in the settings with a show/hide toggle.
- **GeoIP Provider**: MaxMind (local database) or Built-in (ip-api.com).
- **Maximum Log Lines**: the number of log lines included in ban notifications (default: 50).
- Email alerts and alert countries.
- Language preferences.

The UI uses an embedded SQLite database (`fail2ban-ui.db`) for all server configurations and ban events. It is created automatically in the working directory.

## Option 2: Run the container under systemd

This option runs Fail2Ban UI as a containerized service with automatic startup managed by systemd.

### Prerequisites

Podman or Docker must be installed.

```bash
# Podman:
sudo dnf install -y podman

# Docker (if preferred):
sudo dnf install -y docker
sudo systemctl enable --now docker
```

Create the configuration directory:

```bash
sudo mkdir /opt/podman-fail2ban-ui
```

### Create the unit file

Save the following as `/etc/systemd/system/fail2ban-ui-container.service`:

```ini
[Unit]
Description=Fail2Ban UI (Containerized)
After=network.target
Wants=fail2ban.service

[Service]
ExecStart=/usr/bin/podman run --rm \
    --name fail2ban-ui \
    --network=host \
    -v /opt/podman-fail2ban-ui:/config:Z \
    -v /etc/fail2ban:/etc/fail2ban:Z \
    -v /var/log:/var/log:ro \
    -v /var/run/fail2ban:/var/run/fail2ban \
    swissmakers/fail2ban-ui:latest
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

### SELinux-enabled systems

With SELinux enabled, apply the policies that allow the container to communicate with Fail2Ban. The policies are located in `[../container/SELinux/](../container/SELinux/)`.

Install the pre-built modules:

```bash
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

To modify or rebuild the rules yourself:

```bash
checkmodule -M -m -o fail2ban-container-client.mod fail2ban-container-client.te
semodule_package -o fail2ban-container-client.pp -m fail2ban-container-client.mod
semodule -i fail2ban-container-client.pp
```

### Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fail2ban-ui-container.service
sudo systemctl status fail2ban-ui-container.service
```

### Operate the service

```bash
sudo journalctl -u fail2ban-ui-container.service -f   # follow logs
sudo systemctl restart fail2ban-ui-container.service  # restart
sudo systemctl stop fail2ban-ui-container.service     # stop
```

## Contact and support

- Issues, contributions, and feature requests: [GitHub Issues](https://github.com/swissmakers/fail2ban-ui/issues)
- Enterprise support: [Swissmakers GmbH](https://swissmakers.ch)

