# Installation

This document describes the shortest path to a running instance and points to the full deployment guides in the repository.

## Supported platforms

Fail2Ban UI targets Linux hosts. Typical environments are RHEL, Rocky Linux, AlmaLinux, Debian, Ubuntu, and container runtimes in general.

## Container deployment

### Option A: Pre-built image

Run the image with the local connector (Fail2Ban on the same host):

```bash
podman pull swissmakers/fail2ban-ui:latest

podman run -d --name fail2ban-ui --network=host \
  -v /opt/fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /var/log:/var/log:ro \
  swissmakers/fail2ban-ui:latest
```

The same image is published to three registries; use whichever your environment prefers:

* `docker.io/swissmakers/fail2ban-ui`
* `ghcr.io/swissmakers/fail2ban-ui`
* `registry.swissmakers.ch/infra/fail2ban-ui`

Each carries `latest`, a version tag (for example `v1.5.3`), and a commit-SHA tag. Pin to a version tag for reproducible deployments.

Notes on the mounts:

* `/config` stores the SQLite database, settings, and the SSH keys used by the UI.
* `/var/log` is used for log path tests and should be mounted read-only.

### Option B: Compose

Copy one of the examples and adapt it to your environment:

```bash
cp docker-compose.example.yml docker-compose.yml
# or, for Fail2Ban and the UI in one stack:
cp docker-compose-allinone.example.yml docker-compose.yml

podman compose up -d
```

The development stacks under `development/` are also a quick way to evaluate features before a real deployment.

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

### Additional resources

* Full guide: [deployment/container/README.md](../deployment/container/README.md)
* Optional SELinux modules for the container: [deployment/container/SELinux/](../deployment/container/SELinux/)

## systemd deployment (standalone binary)

High-level procedure:

```bash
git clone https://github.com/swissmakers/fail2ban-ui.git /opt/fail2ban-ui
cd /opt/fail2ban-ui

# Build the static CSS assets
./build-tailwind.sh

# Build the Go binary (embeds pkg/web/templates, pkg/web/locales, and pkg/web/static)
go build -o fail2ban-ui ./cmd/server/main.go
```

Then follow [deployment/systemd/README.md](../deployment/systemd/README.md) to install the unit file and configure permissions.

**Note:** On RHEL-family hosts with SELinux enforcing, the Fail2Ban-to-UI HTTP callbacks usually require `setsebool -P nis_enabled 1`. See [security.md](security.md#selinux).

## Production recommendations

* Enable OIDC if your environment supports centralized identity.
* Keep the UI behind a reverse proxy for TLS termination and access control.
* Bind the UI to loopback (`BIND_ADDRESS=127.0.0.1`) when the proxy and the application share a host.

See [reverse-proxy.md](reverse-proxy.md) for proxy configuration and [security.md](security.md) for the recommended deployment posture.
