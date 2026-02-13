# Installation

This document provides a short installation path and points to the full deployment guides in the repository.

Spoiler: They need to be reworked as well we already did with the main files here..

## Supported platforms

Fail2Ban UI targets Linux hosts. Typical environments include RHEL/Rocky/Alma, Debian/Ubuntu, and container environments in general.

## Container deployment

Additional resources:
- Full guide: `deployment/container/README.md`
- SELinux policies: `deployment/container/SELinux/`

### Option A: Pre-built image

Local connector example (Fail2Ban runs on the same host):
```bash
podman pull swissmakers/fail2ban-ui:latest

podman run -d --name fail2ban-ui --network=host \
  -v /opt/fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /var/log:/var/log:ro \
  swissmakers/fail2ban-ui:latest
````

Notes:

* `/config` stores the SQLite DB, settings, and SSH keys used by the UI.
* `/var/log` is used for log path tests and should be mounted read-only to the container.

### Option B: Docker Compose

Use one of the examples and adapt to your environment:

```bash
cp docker-compose.example.yml docker-compose.yml
# or
cp docker-compose-allinone.example.yml docker-compose.yml

podman compose up -d
```
You can also start and test the full dev-stacks from the development folders, it you only want to try it out.

### Option C: Build the image yourself

```bash
git clone https://github.com/swissmakers/fail2ban-ui.git
cd fail2ban-ui
podman build -t fail2ban-ui:dev .
podman run -d --name fail2ban-ui --network=host \
  -v /opt/fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /var/log:/var/log:ro \
  localhost/fail2ban-ui:dev
```

## systemd deployment (standalone)

Additional resources:

* Full guide: `deployment/systemd/README.md`

High-level procedure:

```bash
git clone https://github.com/swissmakers/fail2ban-ui.git /opt/fail2ban-ui
cd /opt/fail2ban-ui

# Build static CSS assets
./build-tailwind.sh

# Build the go-binery
go build -o fail2ban-ui ./cmd/server/main.go
```

Then follow `deployment/systemd/README.md` to install the unit file and configure permissions.

