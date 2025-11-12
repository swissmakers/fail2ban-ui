# Fail2Ban-UI Systemd Setup
This guide provides two methods to **run Fail2Ban-UI as a systemd service**.
1. Systemd service that starts the local compiled binary.
2. Systemd service that starts the fail2ban-ui container.

## For SELinux enabled systems (needed in both cases)
If SELinux is enabled, you must apply the required SELinux policies to allow Fail2Ban to communicate with the Fail2Ban-UI API via port 8080.

Apply the prebuilt SELinux Module with:

```bash
semodule -i fail2ban-curl-allow.pp
```

## Build and running Fail2Ban-UI from Local Source Code
In this case we will run **Fail2Ban-UI from `/opt/fail2ban-ui/`** using systemd.

### Prerequisites
Install **Go 1.22+** and required dependencies:
  ```bash
  sudo dnf install -y golang git whois
  ```
Make sure you setup GeoIP and your country database is available under: `/usr/share/GeoIP/GeoLite2-Country.mmdb`

> **Note:** The local Fail2ban service is optional. Fail2Ban-UI can manage remote Fail2ban servers via SSH or API agents without requiring a local Fail2ban installation.

Clone the repository to `/opt/fail2ban-ui`:
  ```bash
  sudo git clone https://github.com/swissmakers/fail2ban-ui.git /opt/fail2ban-ui
  cd /opt/fail2ban-ui
  sudo go build -o fail2ban-ui ./cmd/server/main.go
  ```

### Create the fail2ban-ui.service
Save this file as `/etc/systemd/system/fail2ban-ui.service`:

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

### Start & Enable the Service
1. Reload systemd to detect our new service:
   ```bash
   sudo systemctl daemon-reload
   ```
2. Enable and start the service:
   ```bash
   sudo systemctl enable fail2ban-ui.service --now
   ```
3. Check the status:
   ```bash
   sudo systemctl status fail2ban-ui.service
   ```

### View Logs
To see the real-time logs of Fail2Ban-UI:
```bash
sudo journalctl -u fail2ban-ui.service -f
```

### Restart or Stop
Restart:
```bash
sudo systemctl restart fail2ban-ui.service
```
Stop:
```bash
sudo systemctl stop fail2ban-ui.service
```

### First Launch & Server Configuration
After starting the service, access the web interface at `http://localhost:8080` (or your configured port).

**Important:** On first launch, you need to:
1. **Enable the local connector** (if Fail2ban runs on the same host), OR
2. **Add a remote server** via SSH or API agent

Go to **Settings** → **Manage Servers** in the web UI to configure your first Fail2ban server.

The UI uses an embedded SQLite database (`fail2ban-ui.db`) to store all server configurations and ban events. This database is automatically created in the working directory.

## Running Fail2Ban-UI as a (Systemd controlled) Container

This method runs Fail2Ban-UI as a **containerized service** with **automatic startup** and handling through systemd.

### Prerequisites

- Ensure **Podman** or **Docker** is installed.

For **Podman**:
```bash
sudo dnf install -y podman
```
For **Docker** (if preferred):
```bash
sudo dnf install -y docker
sudo systemctl enable --now docker
```
Make sure you setup GeoIP and your country database is available under: `/usr/share/GeoIP/GeoLite2-Country.mmdb`

Create the needed folder to store the fail2ban-ui config:
```bash
sudo mkdir /opt/podman-fail2ban-ui
```

### Create the fail2ban-ui-container.service
Save this file as `/etc/systemd/system/fail2ban-ui-container.service`:

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
    -v /usr/share/GeoIP:/usr/share/GeoIP:ro \
    localhost/fail2ban-ui
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

### For SELinux enabled systems
If SELinux is enabled, you must apply the required SELinux policies to allow the container to communicate with Fail2Ban.
The policies are located here: "`../container/SELinux/`"

Apply the prebuilt SELinux Modules with:

```bash
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

#### Manually Compile and Install SELinux Rules

If you want to change or compile the SELinux rules by yourself run:

```bash
checkmodule -M -m -o fail2ban-container-client.mod fail2ban-container-client.te
semodule_package -o fail2ban-container-client.pp -m fail2ban-container-client.mod
semodule -i fail2ban-container-client.pp
```


### Start & Enable the Container Service
1. Reload systemd to detect the new service:
   ```bash
   sudo systemctl daemon-reload
   ```
2. Enable and start the containerized service:
   ```bash
   sudo systemctl enable --now fail2ban-ui-container.service
   ```
3. Check the status:
   ```bash
   sudo systemctl status fail2ban-ui-container.service
   ```

### View Logs
```bash
sudo journalctl -u fail2ban-ui-container.service -f
```

### Restart or Stop
Restart:
```bash
sudo systemctl restart fail2ban-ui-container.service
```
Stop:
```bash
sudo systemctl stop fail2ban-ui-container.service
```

## **Contact & Support**
For issues, visit our GitHub repository:  
🔗 [GitHub Issues](https://github.com/swissmakers/fail2ban-ui/issues)  

For enterprise support:  
🔗 [Swissmakers GmbH](https://swissmakers.ch)
