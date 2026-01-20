# Fail2Ban UI

<div align="center">

**Enterprise-Grade Intrusion Detection System Management Platform**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://www.linux.org/)

*Swiss-made open-source solution for centralized Fail2Ban management across distributed infrastructure*

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Screenshots](#-screenshots) • [Security Notes](#-security-notes)

</div>

---

## 🎯 Overview

**Fail2Ban UI** is a production-ready, enterprise-grade web-based management platform to create a distributed Fail2Ban intrusion detection system. Designed for organizations managing single or multible fail2ban instances. It provides centralized ban-control, real-time monitoring and alerting across all servers.

### Why we Need Fail2Ban UI

Modern enterprises face increasing security challenges with generally distributed infrastructure, cloud deployments, and multi-location operations. Traditional Fail2Ban management requires a manual SSH access to individual servers, manual configuration changes, and lacks centralized visibility. **Fail2Ban UI solves these challenges** by providing:

- **Centralized Management**: Control multible Fail2Ban instances from a single interface
- **Real-Time Visibility**: Monitor ban / security events across your entire proxy / webserver infrastructure (also planned to ingest all via connector to SIEM)
- **Operational Efficiency**: Reduce administrative overhead with automated workflows e.g. auto-banning for recurring IPs, directly  on the firewall.

**Developed by [Swissmakers GmbH](https://swissmakers.ch)** — Trusted by enterprises swisswide for mission-critical security infrastructure.

---

## 🚀 Current Features

### 🏢 Multi-Server Management

**Centralized Control Across Distributed Fail2Ban Instances**

- **Unified Dashboard**: Monitor and manage multiple Fail2Ban servers from a single interface
- **Flexible Connectivity**: Support for local, SSH, (and API agent) connections from Fail2Ban-UI to Fail2Ban Instances
- **API Agent Connector**: Technical preview; Basic API functionality available, full implementation in progress
- **Connection Testing**: Validate backend connectivity before activate them on the management UI

**Use Cases:**
- Multi-datacenter deployments with several reverse proxies
- Hybrid cloud environments
- Also integrate external Webservers

### 📊 Real-Time Security Intelligence

**Malicious Actor Visibility and Analytics**

- **Live Event Monitoring**: Real-time ban events from all configured / connected servers
- **Historical Analysis**: SQLite-based event storage with advanced querying
- **Geographic Intelligence**: Country-based threat analysis and visualization with GeoIP and whois lookups (Option to send the logs to a SIEM is planned)
- **Integrated Lookups**: Whois and GeoIP lookups are performed directly by Fail2Ban UI (no Linux binary dependencies anymore on fail2ban side)
- **Smart Log Filtering**: Automatic selection of most relevant log lines for ban notifications
- **Recurring Threat Detection**: Identify persistent attackers across time windows
- **Ban Insights Dashboard**: Aggregated statistics
- **Event Correlation**: Track attack patterns across multiple servers and jails (planned with Elasticsearch)

**Business Value:**
- Faster threat response times
- Proactive security posture management
- Compliance reporting and audit trails

### 🛡️ Advanced Ban Management

**IP Blocking and Unblocking**

- **Cross-Jail Search**: Find banned IPs across all active jails instantly
- **Bulk Operations**: Manage multiple bans simultaneously
- **Ban History**: Complete audit trail with timestamps, ban-reasons, and context including whois and GeoIP information of the attacker
- **Whitelist Management**: Configure trusted IPs and networks
- **Automatic Unban**: Time-based ban expiration with configurable policies
- **Permanent Ban for Reccuring IPs**: Set a threshold in the Settings, after what amount of Bans a IP is automatically banned permanently on Firewall (Currently Supported Mikrotik/PFSense)


### ⚙️ Configuration Management

- **Remote Configuration**: Edit Fail2Ban jail and filter configurations remotely
- **Jail Management**: Enable/disable jails across multiple servers
- **Filter Testing**: Debug and validate filters using `fail2ban-regex` before enabeling
- **Template Management**: Standardize configurations across server groups (planned)


### 📧 Alerting

**Security Notifications**

- **Multi-Language Email Alerts**: Localized notifications in currently 5 supported languages
- **Country-Based Filtering**: Alert only on threats from specific geographic regions to reduce alert fatigue
- **GeoIP Provider Selection**: Choose between MaxMind (needs a local database) or Built-in (ip-api.com) for geographic lookups
- **SMTP Integration**: Support M365 Mail-Servers with STARTTLS
- **Email Templates**: Currently features a Modern and classic email design (more to come)
- **Alert Aggregation**: This feature is planned for the SIEM-modul

### 🔐 Enterprise Security & Authentication

**Hardened for Production Environments**

- **OIDC Authentication**: Optional OpenID Connect authentication supporting Keycloak, Authentik, and Pocket-ID
  - Secure session management with encrypted cookies (AES-GCM)
  - Automatic logout with provider integration
  - CSRF protection via state parameters
  - Configurable session timeouts
  - Automatic Keycloak client configuration for development environment
- **SELinux Support**: Full compatibility with SELinux-enabled systems and pre-created custom policies
- **Container Security**: Secure containerized deployment with proper best-practices
- **Least Privilege**: Only minimal permissions are used using FACLs and special sudo-rules
- **Audit Logging**: Comprehensive logging for compliance and forensics (planned: Elastic SIEM integration)

### 🌐 Internationalization

- **Multi-Language UI**: English, German (DE/CH), French, Italian, Spanish
- **Localized Content**: All user-facing content translated
- **RTL Support Ready**: Architecture supports right-to-left languages
- **Easy Extension**: Simple JSON-based translation system

### 📱 Modern User Experience

- **Responsive Design**: Full functionality also on mobile devices
- **Login Interface**: Modern, clean authentication UI with OIDC integration
- **Progressive Web App**: Works in offline/restricted environments with local CSS/JS builds only
- **Fast Performance**: Go-based backend with minimal resource footprint
- **Real-Time Updates**: WebSocket-based live event streaming for UI-actions and changes

---

## 📸 Screenshots

### Dashboard Overview
The central command center for monitoring all Fail2Ban instances and security events.

![Dashboard](./screenshots/0_Dashboard.jpg)

### Server Management
Add, configure, and manage multiple Fail2Ban servers from the "Manage Servers" modal.

![Server Management](./screenshots/0.1_Dashboard_Manage_Servers.jpg)

### IP Search and Management
Quickly locate and review / manage banned IPs across all jails and servers.

![IP Search](./screenshots/1_Dashboard_search.jpg)

### Unban Operations
One-click unban action with confirmation dialog.

![Unban IP](./screenshots/2_Dashboard_unban_IP.jpg)

### Configuration Editor
Edit Fail2Ban jail and filter configurations (with syntax highlighting - planned) and validation.

![Configuration Editor](./screenshots/3_Dashboard_edit_filter.jpg)

### Service Management
Reload or restart Fail2Ban services when needed, with integrated change detection.

![Service Reload](./screenshots/4_Dashboard_Reload.jpg)

### Filter Debugging
Test and validate Fail2Ban filters using `fail2ban-regex`.

![Filter Debug](./screenshots/5_Filter_Debug.jpg)

### Settings and Configuration
Comprehensive settings management for alerts, advanced banning, and system preferences.

![Settings](./screenshots/6_Settings.jpg)

![Settings Advanced](./screenshots/7_Settings_Bottom.jpg)

---

## 🏗️ Architecture

### System Components

```
 ┌────────────────────────────────────────────────────────────┐
 │                  Fail2Ban UI Web Interface                 │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
 │  │   Dashboard  │  │  Management  │  │   Settings   │      │
 │  └──────────────┘  └──────────────┘  └──────────────┘      │
 └────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                     Go Backend API Server                      │
│    ┌─────────────────────────────┐    ┌──────────────────────┐ │
│    │ Fail2Ban UI (Backend)       │--->│ Send Alerts via Mail │ │
│    │ - Gin handlers + REST API   │    │ (planned: Elastic)   │ │
│    │ - Vanilla JS + Tailwind UI  │    └──────────────────────┘ │
│  ->│ - SQLite storage            │                             │
│ │  └──────────────┬──────────────┘                             │
│ │                 │                                            │
│ │      ┌──────────┴────────────┐       ┌─────────────────────┐ │
│ │      │ Connector Manager and │-------│ Integrations        │ │
│ │      │ handlers / actions    │       │ Mikrotik / pfSense  │ │
│ │      └────────────────────┬──┘       └─────────────────────┘ │
│ │                           │                                  │
└─│───────────────────────────│──────────────────────────────────┘
  │                           │
  │                           ▼
┌─│─────────────────────────────────────────────────────────────┐
│ │               Connection to remote Server                   │
│ │              ─────────────────────────────                  │
│ │              │             │             │                  │
│ │              ▼             ▼             ▼                  │
│ │          ┌────────┐    ┌────────┐    ┌────────┐             │
│ │          │ Local  │    │  SSH   │    │  API   │             │
│ │          │ Server │    │ Server │    │ Agent  │             │
│ │          └────────┘    └────────┘    └────────┘             │
│ │              │             │             │                  │
│ │              │             │             │                  │
│ │        ┌─────┴─────────────┴─────────────┴─────┐            │
│ │        │ Fail2Ban instances on Reverse Proxies │            │
│ │        │ or remote / local Webserver           │            │
│ │        └─────────────┬─────────────────────────┘            │
│ │                      │                                      │
│ │           ┌──────────┴────────────┐                         │
│ │           │ Report Alerts back to │                         │
│  <----------│ Fail2Ban-UI REST with │                         │
│             │ custom action         │                         │
│             └───────────────────────┘                         │
└───────────────────────────────────────────────────────────────┘
```


### Technology Stack

- **Backend**: Go 1.24+ (Golang)
- **Frontend**: Vanilla JavaScript, Tailwind CSS
- **Database**: SQLite (embedded)
- **Container Runtime**: Podman/Docker compatible
- **Service Management**: systemd
- **Security**: SELinux compatible

---

## 🚀 Quick Start

### Prerequisites

- **Operating System**: Linux (RHEL 8+, Ubuntu 20.04+, Debian 11+, or containerized)
- **Fail2Ban**: At least version 0.10+ installed and configured
- **Go**: Version 1.24+ (only for source builds)
- **Node.js**: Version 16+ (only for source build - Tailwind CSS)
- **Permissions**: Root access to configure FACL and sudo-rules and Fail2Ban socket access

### Installation Methods (Example with mounts for local fail2ban connector)

#### Method 1: Container Deployment (Recommended for Production)

**Option A: Using Pre-built Image**

Pull and run the official image from Docker Hub:
```bash
# Pull the image with podman from Docker Hub (default)
podman pull swissmakers/fail2ban-ui:latest
# or with Docker:
docker pull swissmakers/fail2ban-ui:latest

# Alternative: Pull from Swissmakers registry (fallback)
# podman pull registry.swissmakers.ch/infra/fail2ban-ui:latest
# docker pull registry.swissmakers.ch/infra/fail2ban-ui:latest

# Run the container
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  swissmakers/fail2ban-ui:latest
```

**Option B: Build from Source**

Build your own container image:
```bash
# Clone the repository
git clone https://github.com/swissmakers/fail2ban-ui.git
cd fail2ban-ui

# Build the image
sudo podman build -t fail2ban-ui:dev .
# or with Docker:
sudo docker build -t fail2ban-ui:dev .

# Run the container
sudo podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  localhost/fail2ban-ui:dev
```

**Option C: Using Docker Compose**

For easier management, use Docker Compose:
```bash
# Copy the example file
cp docker-compose.example.yml docker-compose.yml
# or
cp docker-compose-allinone.example.yml docker-compose.yml

# Edit docker-compose.yml to customize (e.g., change PORT)
# Then start:
podman compose up -d 
# or
docker-compose up -d
```

**Custom Port Configuration**

Change the default port (8080) using the `PORT` environment variable:
```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -e PORT=3080 \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  swissmakers/fail2ban-ui:latest
```

**OIDC Authentication Configuration (Optional)**

Enable OIDC authentication by setting the required environment variables. This protects the web UI with your identity provider. The logout flow automatically redirects back to the login page after successful provider logout.

**Basic Configuration:**
```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -e OIDC_ENABLED=true \
  -e OIDC_PROVIDER=keycloak \
  -e OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm \
  -e OIDC_CLIENT_ID=fail2ban-ui \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  swissmakers/fail2ban-ui:latest
```

**Note:** The logout URL is automatically constructed for all supported providers. For Keycloak, ensure the post-logout redirect URI is configured in your client settings (see [Security Notes](#-security-notes) for details).

**Provider-Specific Examples:**

**Keycloak:**
```bash
-e OIDC_ENABLED=true \
-e OIDC_PROVIDER=keycloak \
-e OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm \
-e OIDC_CLIENT_ID=fail2ban-ui \
-e OIDC_CLIENT_SECRET=your-client-secret \
-e OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
# OIDC_LOGOUT_URL is optional - automatically constructed if not set
# Ensure "Valid post logout redirect URIs" in Keycloak includes: https://fail2ban-ui.example.com/auth/login
```

**Authentik:**
```bash
-e OIDC_ENABLED=true \
-e OIDC_PROVIDER=authentik \
-e OIDC_ISSUER_URL=https://authentik.example.com/application/o/your-client-slug/ \
-e OIDC_CLIENT_ID=fail2ban-ui \
-e OIDC_CLIENT_SECRET=your-client-secret \
-e OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
```

**Pocket-ID:**
```bash
-e OIDC_ENABLED=true \
-e OIDC_PROVIDER=pocketid \
-e OIDC_ISSUER_URL=https://pocket-id.example.com \
-e OIDC_CLIENT_ID=fail2ban-ui-client \
-e OIDC_CLIENT_SECRET=your-secret \
-e OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
```

**Advanced Options:**
```bash
-e OIDC_SCOPES=openid,profile,email,groups \
-e OIDC_SESSION_MAX_AGE=7200 \
-e OIDC_USERNAME_CLAIM=preferred_username \
-e OIDC_SESSION_SECRET=your-32-byte-secret
```

**Note:** If `OIDC_SESSION_SECRET` is not provided, a random secret will be generated on startup. For production, it's recommended to set a fixed secret.

Access the web interface at `http://localhost:3080`.

**Disable External IP Lookup** (Privacy)

By default, the web UI displays your external IP address by querying external services. For privacy reasons, you can disable this feature using the `DISABLE_EXTERNAL_IP_LOOKUP` environment variable:

```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -e DISABLE_EXTERNAL_IP_LOOKUP=true \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  swissmakers/fail2ban-ui:latest
```

When set, the "Your ext. IP:" display will be completely hidden and no external IP lookup requests will be made.

**Volume Mounts Explained**

| Volume | Required | Purpose |
|--------|----------|---------|
| `/config` | ✅ Yes | Stores SQLite database, application settings, and SSH keys for remote connections |
| `/etc/fail2ban` | ✅ Yes* | Access to Fail2Ban configuration files (jails, filters, actions) |
| `/var/run/fail2ban` | ✅ Yes* | Access to Fail2Ban control socket for local management |
| `/var/log` | ✅ Yes* | Read-Only | `:ro` | System log files for automated logpath tests on jail management. |
| `/path/to/your/GeoIPFolder` | ⚠️ Optional | Read-Only | `:ro` | MaxMind GeoIP databases (only needed if using MaxMind provider) |

*Required only if managing a local Fail2Ban instance as well. Not needed for remote-only deployments.

**📖 [Complete Container Deployment Guide](./deployment/container/README.md)** - Detailed documentation including volume descriptions, SELinux configuration, and troubleshooting.

#### Method 2: Systemd Service (Standalone)

**Clone and build:**
```bash
git clone https://github.com/swissmakers/fail2ban-ui.git /opt/fail2ban-ui
cd /opt/fail2ban-ui

# Build Tailwind CSS (optional, for offline use)
./build-tailwind.sh

# Build Go application
go build -o fail2ban-ui ./cmd/server/main.go
```

**📖 [Complete Systemd Setup Guide](./deployment/systemd/README.md)**

**OIDC Authentication for Systemd Deployment:**

When running as a systemd service, set OIDC environment variables in the systemd service file:

```ini
[Service]
Environment="OIDC_ENABLED=true"
Environment="OIDC_PROVIDER=keycloak"
Environment="OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm"
Environment="OIDC_CLIENT_ID=fail2ban-ui"
Environment="OIDC_CLIENT_SECRET=your-client-secret"
Environment="OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback"
```

See the [Security Notes](#-security-notes) section for complete OIDC configuration details.

### First Launch

1. **Access the Web Interface**
   - Navigate to `http://localhost:8080` (or your configured port)
   - Default port: `8080` (configurable via `PORT` environment variable or in UI settings)

2. **Add Your First Server**
   - **Local Server**: Enable the local connector if Fail2Ban runs on the same host
   - **Remote Server**: Add via SSH or API agent connection

3. **Configure Settings**
   - Set up email alerts
   - Configure language preferences
   - Adjust security settings

---

## 📚 Documentation

### Deployment Guides

- **[Container Deployment Guide](./deployment/container/README.md)**: 
  - Building container images from source
  - Running containers with Docker/Podman
  - Volume mount explanations (required vs optional)
  - Custom port configuration via `PORT` environment variable
  - Docker Compose examples
  - SELinux configuration
  - Troubleshooting common issues

- **[Systemd Service Setup](./deployment/systemd/README.md)**: Standalone installation and service configuration for non-containerized deployments

- **[SELinux Configuration](./deployment/container/SELinux/)**: Security policies for SELinux-enabled systems

### Connector Types

Fail2Ban UI supports three types of connectors to manage remote and or local only Fail2Ban instances:

#### Local Connector

The local connector manages Fail2Ban on the same host/vm/container-stack where Fail2Ban UI runs. It does that by directly communicating with the local Fail2Ban instance via socked, without network overhead.

**How it works:**
- Accesses the Fail2Ban control socket at `/var/run/fail2ban/fail2ban.sock`
- Reads and writes configuration files directly to `/etc/fail2ban/`
- Requires FACL (File Access Control Lists) rules and passwordless sudo permissions to `/usr/bin/fail2ban-client` (if not running as privileged e.g. in a container)

**When to use:**
- ✅ Fail2Ban UI and Fail2Ban run on the same server
- ✅ Single-server deployments
- ✅ Development or testing environments
- ✅ Maximum performance with zero network latency
- ✅ Simplest setup with minimal configuration

#### SSH Connector

The SSH connector connects to remote Fail2Ban instances over SSH, enabling centralized management of distributed infrastructure. (no need to install fail2ban-UI everyware)

**How it works:**
- Establishes SSH connections to remote servers using key-based authentication
- Transfers and manages configuration files encrypted over SSH
- Automatically deploys custom Fail2Ban actions to remote instances for callback API ban-communication
- Executes `fail2ban-client` commands remotely via SSH

**When to use:**
- ✅ Managing Fail2Ban instances on remote servers supporting SSH
- ✅ Multi-server deployments across different hosts / reverse proxies
- ✅ When Fail2Ban UI runs on a dedicated management server
- ✅ Environments where direct socket access is not possible

**Requirements:**
- SSH key-based authentication (passwordless login)
- Network connectivity from Fail2Ban UI host to remote server
- Service account on remote server with appropriate permissions
- Sudo access for Fail2Ban commands (configured via sudoers)
- File system ACLs on remote server with write-permissions for `/etc/fail2ban/` directory

#### API Agent Connector *(Technical Preview)*

The API agent connector uses a lightweight agent installed on remote servers that communicates bouth ways, to and from Fail2Ban UI via REST API.

**Status:** Implementation in progress

### Configuration Values

#### Fail2Ban Callback URL

The **Fail2Ban Callback URL** is a critical setting that determines how Fail2Ban instances send ban alerts back to Fail2Ban UI. This URL is embedded in a custom Fail2Ban action file as well as the secret that gets deployed to all managed Fail2Ban instances (both local and SSH). For the API agent connections, only the Callback URL and Secret is relevant.

**How it works:**
- When a Fail2Ban instance bans an IP, it executes the custom action which sends a POST request including the secret to the callback URL (`/api/ban` endpoint)
- If the secret is missing or wrong the request is dropped.
- If the secret is valid, Fail2Ban-UI receives these notifications and stores them in the database for monitoring and analysis
- The callback URL is automatically synchronized with the server port when using the default localhost pattern

**Configuration Guidelines:**

1. **Local Deployments:**
   - Use the same port as Fail2Ban UI: `http://127.0.0.1:8080` (or your configured port)
   - The callback URL automatically updates when you change the server port
   - Example: If Fail2Ban UI runs on port `3080`, use `http://127.0.0.1:3080`

2. **Reverse Proxy Setups:**
   - Use your TLS-encrypted endpoint: `https://fail2ban.example.com`
   - Ensure the reverse proxy forwards requests to the correct Fail2Ban UI port
   - The callback URL must be accessible from all Fail2Ban instances (local and remote)

3. **Port Changes:**
   - When you change the Fail2Ban UI port (via `PORT` environment variable or UI settings), the callback URL automatically updates if it's using the default localhost pattern

**Privacy Settings**

- **External IP Lookup**: By default, the web UI displays your external IP address. To disable this feature for privacy reasons, set the `DISABLE_EXTERNAL_IP_LOOKUP` environment variable to `true` or `1`. This will hide the "Your ext. IP:" display and prevent any external IP lookup requests.
   - For custom callback URLs (e.g., reverse proxy or custom IP), you must manually update them to match your setup

**Important Notes:**
- The callback URL must be accessible from all Fail2Ban instances that need to send alerts
- For remote Fail2Ban instances, ensure network connectivity to the callback URL
- If using a reverse proxy, configure it to forward `/api/ban` requests to Fail2Ban UI
- The callback URL is stored in `/etc/fail2ban/action.d/ui-custom-action.conf` on each managed Fail2Ban instance

#### Adding a Local Server after initial setup

The local connector allows managing Fail2Ban on the same host where Fail2Ban UI runs.

**Enable in UI:**
1. Navigate to **Settings** → **Manage Servers**
2. Enable **Local Connector**
3. Test connection to verify access

#### Adding an SSH Server after initial setup

Connect to remote Fail2Ban instances via SSH for centralized management.

**Prerequisites:**
- SSH key-based authentication (passwordless login)
- Network connectivity from UI host to remote server
- Service account with appropriate permissions

**Recommended Service Account Setup:**

```bash
# Create dedicated service account
sudo useradd -r -s /bin/bash sa_fail2ban

# Configure sudoers for Fail2Ban operations
sudo visudo -f /etc/sudoers.d/fail2ban-ui
```

Add the following sudoers configuration:
```
sa_fail2ban ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *
sa_fail2ban ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart fail2ban
```

**Set file system ACLs:**
```bash
# Grant read/write access to Fail2Ban configuration directory
sudo setfacl -Rm u:sa_fail2ban:rwX /etc/fail2ban
sudo setfacl -dRm u:sa_fail2ban:rwX /etc/fail2ban
```

**Add Server in UI:**
1. Navigate to **Settings** → **Manage Servers**
2. Click **Add Server**
3. Select **SSH** connection type
4. Configure:
   - **Name**: Descriptive server identifier
   - **Host**: IP address or hostname (ip is always better, if DNS fails for some reason)
   - **Port**: SSH port (default: 22)
   - **SSH User**: Service account username
   - **SSH Key**: Select from `~/.ssh/` directory
5. Tick "Enable connector"
6. Save configuration
7. Click **Test Connection** to verify

---

### 🔒 Security Notes

#### Network Security Best Practices

- **Reverse Proxy**: Use nginx or Apache as reverse proxy with SSL/TLS termination to secure the Fail2ban-UI
- **VPN Access**: Require VPN connection for access to Fail2Banu-UI only
- **IP Whitelisting**: Restrict access to specific IPs / ranges e.g. internal IT

#### Authentication and Authorization

##### OIDC Authentication (Optional)

Fail2ban UI supports optional OIDC (OpenID Connect) authentication via environment variables. When enabled, all routes are protected and users must authenticate through the configured OIDC provider. The authentication flow includes automatic logout handling and redirects back to the login page.

**Supported Providers:**
- **Keycloak**: Enterprise identity and access management (recommended)
- **Authentik**: Full-featured identity provider with OIDC support
- **Pocket-ID**: Modern identity provider with passkey support

**Development Setup:**
For local development and testing, a complete OIDC environment is available in `development/oidc/` with automatic Keycloak client configuration. See [Development Documentation](./development/oidc/README.md) for details.

**Required Environment Variables (when OIDC enabled):**
```bash
OIDC_ENABLED=true
OIDC_PROVIDER=keycloak|authentik|pocketid
OIDC_ISSUER_URL=https://auth.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
```

**Optional Environment Variables:**
```bash
OIDC_SCOPES=openid,profile,email          # Default: openid,profile,email
OIDC_SESSION_SECRET=your-secret-key        # Auto-generated if not provided
OIDC_SESSION_MAX_AGE=3600                  # Session timeout in seconds (default: 3600)
OIDC_USERNAME_CLAIM=preferred_username     # Claim to use as username (default: preferred_username)
OIDC_LOGOUT_URL=https://auth.example.com/logout  # Provider logout URL (optional, auto-constructed if not set)
OIDC_CLIENT_SECRET_FILE=/path/to/secret-file     # Path to client secret file (for auto-configuration)
OIDC_SKIP_VERIFY=false                     # Skip TLS verification (dev only, default: false)
```

**Configuration Examples:**

**Keycloak:**
```bash
OIDC_ENABLED=true
OIDC_PROVIDER=keycloak
OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm
OIDC_CLIENT_ID=fail2ban-ui
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
# OIDC_LOGOUT_URL is optional - automatically constructed if not set
# For Keycloak, ensure "Valid post logout redirect URIs" includes: https://fail2ban-ui.example.com/auth/login
```

**Authentik:**
```bash
OIDC_ENABLED=true
OIDC_PROVIDER=authentik
OIDC_ISSUER_URL=https://authentik.example.com/application/o/your-client-slug/
OIDC_CLIENT_ID=fail2ban-ui
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
```

**Pocket-ID:**
```bash
OIDC_ENABLED=true
OIDC_PROVIDER=pocketid
OIDC_ISSUER_URL=https://pocket-id.example.com
OIDC_CLIENT_ID=fail2ban-ui-client
OIDC_CLIENT_SECRET=your-secret
OIDC_REDIRECT_URL=https://fail2ban-ui.example.com/auth/callback
# OIDC_LOGOUT_URL is optional - automatically constructed if not set
```

**Security Notes:**
- Session cookies are encrypted using AES-GCM
- Sessions are httpOnly and secure (automatically detects HTTPS/HTTP context)
- CSRF protection via state parameter in OAuth flow
- Session timeout is configurable (default: 1 hour)
- Automatic logout URL construction for all supported providers
- When OIDC is disabled, the application works without authentication (backward compatible)
- Callback endpoints (`/api/ban`, `/api/unban`) remain accessible without OIDC authentication (protected by callback secret)

**Other Security Practices:**
- **SSH Key Management**: Use strong SSH keys like 4096-bit RSA or even better Ed25519. When using RSA no smaller bit size please.
- **Service Accounts**: Use dedicated service accounts, not personal accounts
- **Sudoers Configuration**: Minimal sudo permissions, no passwordless full sudo
- **Callback Secret**: Auto-generated secret authenticates all ban notification requests; keep it secure and never expose

#### Data Protection

- **Database Permissions**: Restrict SQLite database file permissions (600)
- **Log Files**: Secure log file access and don't forget to setup a rotation
- **Backup Encryption**: It's always a good idea, to encrypt backups of configuration and database files

#### SELinux Configuration

For SELinux-enabled systems, apply the required policies:

```bash
# Basic rule to allow Fail2Ban to access the UI API
semodule -i fail2ban-curl-allow.pp

# Container deployment policies
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

**📖 [SELinux Policies Documentation](./deployment/container/SELinux/)**

---

### 🗄️ Database Notes

#### SQLite Database Schema

Fail2Ban UI uses an embedded SQLite database (`fail2ban-ui.db`) for persistent storage:

**Tables:**
- **`servers`**: Server configurations (local, SSH, API agent)
- **`app_settings`**: Application preferences and settings of Fail2Ban-UI
- **`ban_events`**: Historical ban records with full context
- **`permanent_blocks`**: Permanent block records for integrations

**Data Retention:**
- Ban events are stored indefinitely (configurable)
- Automatic database migrations on version updates
- Backup recommended before major updates

---

### 🌍 Internationalization Notes

#### Currently Supported Languages

- **English** (en) - Default
- **German** (de, de_CH) - Standard and Swiss variants
- **French** (fr)
- **Italian** (it)
- **Spanish** (es)

#### Adding New Languages

1. Create translation file: `internal/locales/{language_code}.json`
2. Copy structure from `internal/locales/en.json`
3. Translate all key-value pairs
4. Test in UI: **Settings** → **Language** → Select new language

**Translation File Structure:**
```json
{
  "page.title": "Fail2ban UI Dashboard",
  "nav.dashboard": "Dashboard",
  "nav.settings": "Settings",
  ...
}
```

---

### 📊 API Reference

Fail2Ban UI provides a RESTful API for programmatic access:

#### Endpoints

**Server Management:**
- `GET /api/servers` - List all configured servers
- `POST /api/servers` - Add or update server
- `DELETE /api/servers/:id` - Remove server
- `POST /api/servers/:id/test` - Test server connection

**Jail Management:**
- `GET /api/summary` - Get summary of all jails
- `POST /api/jails/:jail/unban/:ip` - Unban IP address
- `GET /api/jails/manage` - List jail management status
- `POST /api/jails/manage` - Update jail enabled states

**Configuration:**
- `GET /api/jails/:jail/config` - Get jail/filter configuration
- `POST /api/jails/:jail/config` - Update jail/filter configuration

**Events and Analytics:**
- `GET /api/events/bans` - List ban events
- `GET /api/events/bans/stats` - Get ban statistics
- `GET /api/events/bans/insights` - Get ban insights and analytics

**Settings:**
- `GET /api/settings` - Get application settings
- `POST /api/settings` - Update application settings
- `POST /api/settings/test-email` - Test email configuration

**Filter Debugging:**
- `GET /api/filters` - List available filters
- `POST /api/filters/test` - Test filter against log lines

**Authentication (OIDC):**
- `GET /auth/login` - Show login page or redirect to OIDC provider
- `GET /auth/callback` - OIDC callback handler
- `GET /auth/logout` - Logout and redirect to provider logout
- `GET /auth/status` - Get authentication status
- `GET /auth/user` - Get current user information

**Service Control:**
- `POST /api/fail2ban/restart` - Restart Fail2Ban service

**Notifications:**
- `POST /api/ban` - Receive ban notification from Fail2Ban
  - **Authentication**: Requires `X-Callback-Secret` header with valid secret
  - **Request Body**: JSON with `serverId`, `ip`, `jail`, `hostname`, `failures`, `logs`
  - **Response**: 200 OK on success, 401 Unauthorized if secret is invalid

---

## 🛠️ Troubleshooting

### Common Issues

#### UI Not Accessible

**Symptoms:** Cannot access web interface

**Solution / Check:**
```bash
# Check if service is running
systemctl status fail2ban-ui

# Check firewall rules
sudo firewall-cmd --list-ports
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload

# Check logs
journalctl -u fail2ban-ui.service -f
```

#### No Servers Configured

**Symptoms:** Empty dashboard, no servers visible

**Solution / Check:**
1. Navigate to **Settings** → **Manage Servers**
2. Enable **Local Connector** (if Fail2Ban runs locally)
3. Add remote server via SSH or API agent
4. Verify server connection status

#### OIDC Authentication Issues

**Symptoms:** Cannot login, redirected to provider but authentication fails

**Solution / Check:**
1. **Verify OIDC Configuration:**
   ```bash
   # Check environment variables
   podman exec fail2ban-ui env | grep OIDC
   ```

2. **Check Provider Connectivity:**
   - Verify `OIDC_ISSUER_URL` is accessible
   - Check that issuer URL matches provider's discovery document
   - For Keycloak: Ensure realm exists and is enabled

3. **Verify Client Configuration:**
   - Client ID and secret must match provider configuration
   - Redirect URI must exactly match: `{your-url}/auth/callback`
   - For Keycloak: Ensure "Valid post logout redirect URIs" includes `{your-url}/auth/login`

4. **Check Logs:**
   ```bash
   podman logs fail2ban-ui | grep -i oidc
   ```

5. **Development Environment:**
   - See [Development OIDC Setup](./development/oidc/README.md) for complete setup guide
   - Automatic Keycloak client configuration available in development environment

#### SSH Connection Issues

**Symptoms:** Cannot connect to remote server

**Solution / Check:**
```bash
# Test SSH connection manually
ssh -i ~/.ssh/your_key user@remote-host

# Verify SSH user permissions
sudo -l -U sa_fail2ban

# Check ACLs on /etc/fail2ban
getfacl /etc/fail2ban

# Enable debug mode in UI settings for detailed error messages
```

#### Local Connector Not Working

**Symptoms:** Local server shows as disconnected

**Solution / Check:**
```bash
# Verify Fail2Ban is running
sudo systemctl status fail2ban

# Check socket permissions
ls -la /var/run/fail2ban/fail2ban.sock

# Verify UI has access (runs as root or has sudo permissions)
sudo fail2ban-client status
```

#### Database Errors

**Symptoms:** Database-related errors in logs

**Solution / Check:**
```bash
# Check database file permissions
ls -la /opt/fail2ban-ui/fail2ban-ui.db

# Verify database integrity
sqlite3 /opt/fail2ban-ui/fail2ban-ui.db "PRAGMA integrity_check;"

# Backup and recreate if corrupted
cp fail2ban-ui.db fail2ban-ui.db.backup
```

---

## 🤝 Contributing

We welcome contributions from the community! Whether it's bug fixes, feature enhancements, or documentation improvements, your contributions help make Fail2Ban UI better for everyone.

### How to Contribute

1. **Fork the Repository**
   ```bash
   git clone https://github.com/swissmakers/fail2ban-ui.git
   cd fail2ban-ui
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow Go coding standards
   - Add tests for new features
   - Update documentation as needed

4. **Commit Your Changes**
   ```bash
   git commit -m "Add: Description of your feature"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Contribution Guidelines

- **Code Style**: Follow Go standard formatting (`gofmt`)
- **Testing**: Test your changes thoroughly
- **Documentation**: Update README and inline documentation
- **Commit Messages**: Use clear, descriptive commit messages
- **Pull Requests**: Provide detailed description of changes

---

## 📜 License

Fail2Ban UI is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

This means:
- ✅ **Free to use** in commercial and non-commercial projects
- ✅ **Free to modify** and distribute
- ✅ **Source code available** for inspection and auditing
- ⚠️ **Copyleft**: Modifications must be released under the same license

**Full License Text:** [LICENSE](./LICENSE)

---

## 🏢 Enterprise Support

### Professional Services

**Swissmakers GmbH** offers professional services for Fail2Ban UI:

- **Enterprise Deployment**: Custom deployment and configuration
- **Training and Support**: On-site or remote training sessions
- **Custom Development**: Feature development and integrations
- **Security Audits**: Security assessment and hardening

**Contact:** [https://swissmakers.ch](https://swissmakers.ch)

### Community Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/swissmakers/fail2ban-ui/issues)
- **Documentation**: Comprehensive guides and API reference
- **Community**: Join discussions and share experiences

---

## 🙏 Acknowledgments

Fail2Ban UI is built on the foundation of the excellent [Fail2Ban](https://www.fail2ban.org/) project and the open-source community.

**Special Thanks:**
- Fail2Ban developers and contributors
- Go community and ecosystem
- All contributors and users of Fail2Ban UI

---

<div align="center">

**Fail2Ban UI** — *Enterprise-Grade Intrusion Detection System Management*

</div>