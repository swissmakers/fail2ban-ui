# Fail2Ban UI

**Enterprise-Grade Intrusion Detection System Management Platform**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://www.linux.org/)

Fail2Ban UI is a management platform for operating Fail2Ban across one or more Linux hosts. It provides a central place to review bans, search and unban IP addresses, manage jails and filters, and receive notifications.

The project is maintained by Swissmakers GmbH and released under AGPL-3.0.

[Quick start](#quick-start-container) - [Documentation](#documentation) - [Configuration reference](docs/configuration.md) - [Architecture](docs/architecture.md) - [Screenshots](#screenshots)

## What this project does

Fail2Ban UI does not replace Fail2Ban. Ban decisions are still made by the Fail2Ban daemon on each host. The UI connects to existing instances and adds:

* A dashboard of active jails and recent ban/unban activity, updated in real time over WebSocket
* A server manager for local, SSH-connected, and agent-connected Fail2Ban instances
* Centralized search, ban, and unban operations across all jails and servers
* Remote jail and filter configuration management (depending on connector capabilities)
* Filter debugging with live log-pattern testing
* Ban insights with a Kibana-like ban/unban timeline, incident comparison to isolate repeat attackers, one-click permanent blocking of a whole time range, and country-level analytics
* Recurring-offender handling with permanent blocks on MikroTik, pfSense, and OPNsense
* Persistent event history and permanent-block records, with data management built in
* Configurable alerts over Email (SMTP), Webhook, and Elasticsearch, with GeoIP/Whois enrichment and country filtering
* Optional OIDC login (Keycloak, Authentik, Pocket-ID)
* Least-privilege, SELinux-aware deployment patterns

## How it works

The UI runs as a single Go binary, in a container or as a systemd service. Two independent data paths connect it to the managed hosts:

* **Control path** (blue) - Fail2ban UI manages each Fail2Ban instance through one of three connectors (see below): reading jail status, banning and unbanning, editing configuration, restarting the service.
* **Event path** (green) - a custom Fail2Ban action on each host posts every ban and unban event back to the UI over HTTP, authenticated by a shared callback secret. The UI stores the event, broadcasts it to connected browsers, and triggers alerts and advanced actions.

[![Architecture-Diagram](docs/diagrams/architecture.drawio.svg)](docs/diagrams/architecture.drawio.svg)

See [docs/architecture.md](docs/architecture.md) for the data-flow description.

## Connector types

| Connector | Typical use | Notes |
|-----------|-------------|-------|
| Local | Fail2Ban runs on the same host as the UI | Uses the Fail2Ban Unix socket and local files |
| SSH | Manage remote hosts without installing an agent | Key-based SSH and remote `fail2ban-client`; requires a dedicated service account with minimal sudo rules. Can optionally open a reverse SSH tunnel so ban callbacks reach the UI from hosts that cannot connect to it directly (NAT, isolated DMZ) |
| Agent | Environments where SSH from the UI host is not desired | HTTP agent runs on the Fail2Ban host; see [fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent) and the prebuilt image [swissmakers/fail2ban-ui-agent](https://hub.docker.com/r/swissmakers/fail2ban-ui-agent) |

## Quick start (container)

### Prerequisites

* A Linux host with Podman or Docker
* For a local Fail2Ban instance: access to `/etc/fail2ban` and `/var/run/fail2ban` from the container

### Procedure

Run the container with the local connector:

```bash
podman run -d --name fail2ban-ui --network=host \
  -v /opt/fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /var/log:/var/log:ro \
  swissmakers/fail2ban-ui:latest
```

### Verification

1. Open `http://localhost:8080`.
2. In the UI, go to **Settings -> Manage Servers**, enable the local connector, and click **Test connection**.

### Next steps

For Compose, systemd, SELinux, and the remote connectors, see the documentation below.

## Documentation

* [Installation](docs/installation.md)
* [Configuration reference](docs/configuration.md) - environment variables, callback URL and secret, OIDC
* [Architecture overview](docs/architecture.md)
* [Reverse proxy guide](docs/reverse-proxy.md)
* [Security guidance](docs/security.md) - recommended deployment posture
* [Alert providers](docs/alert-providers.md) - Email, Webhook, Elasticsearch
* [Threat intelligence](docs/threat-intel.md) - AlienVault OTX, AbuseIPDB
* [Webhook integration guide](docs/webhooks.md)
* [API reference](docs/api.md)
* [Troubleshooting](docs/troubleshooting.md)

Deployment guides in this repository:

* Container: [deployment/container/README.md](deployment/container/README.md)
* systemd: [deployment/systemd/README.md](deployment/systemd/README.md)
* Optional container SELinux modules (socket/log access): [deployment/container/SELinux/](deployment/container/SELinux/) - host-side Fail2Ban `curl` callbacks often need the `nis_enabled` boolean instead; see [docs/security.md](docs/security.md#selinux)

Development and testing stacks:

* OIDC dev stack: [development/oidc/README.md](development/oidc/README.md)
* SSH and local connector dev stack: [development/ssh_and_local/README.md](development/ssh_and_local/README.md)

## Security notes

Think before exposing the UI:

* Do not expose your Fail2ban-UI directly to the public Internet. Place it behind a reverse proxy, VPN, or firewall rules, and enable OIDC where possible.
* The SSH connector should use a dedicated service account with minimal sudo permissions and ACLs - at minimum `sudo fail2ban-client *` and `sudo systemctl restart fail2ban`.
* All IP addresses are validated with strict IPv4/IPv6/CIDR parsing before they reach any integration or command, which prevents command injection.
* WebSocket connections are protected by same-origin validation and require authentication when OIDC is enabled.
* For production proxy examples and WebSocket requirements, see [docs/reverse-proxy.md](docs/reverse-proxy.md).

See [docs/security.md](docs/security.md) for details.

## Screenshots

A set of screenshots is available in `screenshots/`

### Main dashboard

[![Dashboard](screenshots/0_Dashboard.png)](screenshots/0_Dashboard.png)

Overview of all active jails, banned IPs, and real-time statistics, total bans, recent activity, and quick access to the main features.

#### Unban IP
![Unban IP](screenshots/0.1_Dashboard_unban_IP.png)
Unban an IP address directly from the dashboard. A confirmation dialog shows the affected jail before the unban runs.

### Server Management
![Manage Servers](screenshots/1_Dashboard_Manage_Servers.png)
Server management modal for configuring / adding and managing multiple Fail2Ban instances. Supports local, SSH, and API agent connections.

### Jail / Filter Management
![Manage Jails](screenshots/1.1_Dashboard_Manage_Jails.png)
Overview of all configured jails with their enabled/disabled status. Allows centralized management of jail configurations across multiple servers.

#### Edit Jail Configuration
![Edit Jail](screenshots/1.2_Dashboard_Manage_Jails_Edit.png)
Clicking **Edit Filter / Jail** opens the configuration editor. Edit the jail and filter settings, add or change log paths and test them, then save -> the change is pushed to the managed host and Fail2Ban is reloaded.

#### Logpath Test
![Logpath Test](screenshots/1.3_Dashboard_Manage_Jails_Edit_Logpathtest.png)
Logpath testing resolves the configured paths, including wildcards and Fail2Ban variables, and reports one of three results per path: found (green, with the matched files), not found (red), or cannot verify (yellow). The yellow state means the connector's SSH user cannot read the log directory. It is a warning, not a failure. Fail2Ban runs as root on the managed host and will still read the path, so the jail can be enabled.

#### Create new Filter
![Create Filter](screenshots/1.4_Dashboard_Manage_Jails_Create_Filter.png)
The first button opens the modal for creating new Fail2Ban filter files. Includes filter configuration editor with syntax highlighting and validation.

#### Create new Jail
![Create Jail](screenshots/1.5_Dashboard_Manage_Jails_Create_Jail.png)
The second button opens the jail creation modal for setting up new jails. It supports separate jail definitions with custom parameters and filter selection.

### Search Functionality
![Search](screenshots/1.6_Dashboard_search.png)
Search for an IP address across all active jails of every configured server. The result lists each jail that currently bans the address, so it can be unbanned in the right place.

### Internal Log Overview
![Log Overview](screenshots/2_Dashboard_Log_Overview.png)
Comprehensive log overview showing ban / unban events, timestamps, and associated jails and recurring offenders. Provides detailed information about past security events.

#### Whois Information
![Whois](screenshots/2.1_Dashboard_Log_Overview_Whois.png)
Whois lookup modal displaying detailed information about banned IP addresses, including geographic location, ISP details, and network information.

#### Ban Logs
![Ban Logs](screenshots/2.2_Dashboard_Log_Overview_BanLogs.png)
Detailed ban log view showing log lines that triggered the ban, timestamps, and context information for each security event.

#### Ban Insights

[![Ban Insights](screenshots/2.3_Dashboard_Log_Overview_BanInsights.png)](screenshots/2.3_Dashboard_Log_Overview_BanInsights.png)

Ban Insights brings SIEM-like analysis to environments without a full SIEM. The ban and unban activity timeline works similar like the one in Kibana -> drag to zoom into a time range, use presets from 8 hours to 30 days, or define a custom range of up to 12 months, so spikes and attack patterns become visible at a glance.

Typical workflows:

* **Correlate two incidents.** Pin one spike as Incident A and another as Incident B -> for example, last week's attack and this week's. The incident compare lists the IPs present in both. Addresses that return across incidents are repeat attackers rather than false positives, and can be banned permanently right to the recurring-offenders list.
* **Block a botnet in one click.** Select a time range in which no legitimate user is normally active, such as a nightly spike, and permanently block every IP in it on the configured firewall integration (MikroTik, pfSense, OPNsense).

The modal also suggests similar past periods, exports IP lists as CSV or JSON, and shows country-level analytics on an interactive 3D globe together with the top recurring IPs.

### Filter Debugging
![Filter Debug](screenshots/3_Filter_Debug.png)
Filter debugging interface for testing Fail2Ban filter regex patterns against log lines. Helps validate filter configurations before deployment.

#### Filter Test Results
![Filter Test Results](screenshots/3.1_Filter_Debug_Testresult.png)
Results from filter testing showing matched lines, regex performance, and validation feedback. Displays which log lines match the filter pattern.

### Settings
![Settings](screenshots/4_Settings.png)
Main settings page with sections for different configuration categories including general settings, advanced ban actions, alert settings, and global fail2ban settings.

#### Debug Console
![Debug Console](screenshots/4.1_Settings_DebugConsole.png)
When enabled, the debug console streams the live application log into the browser -> useful for troubleshooting without querying the container logs manually. Leave it disabled in normal operation.

#### Advanced ban actions

[![Advanced Ban Actions](screenshots/4.2_Settings_AdvancedBanActions.png)](screenshots/4.2_Settings_AdvancedBanActions.png)

Permanent blocking, firewall integrations (MikroTik, pfSense, OPNsense), and recurring-offender thresholds.

#### Alert settings

[![Alert Settings](screenshots/4.3_Settings_AlertSettings.png)](screenshots/4.3_Settings_AlertSettings.png)

Three alert providers, Email (SMTP), Webhook, and Elasticsearch, with country filtering, GeoIP provider selection, and per-event toggles. See [docs/alert-providers.md](docs/alert-providers.md).

#### Global settings

[![Global Settings](screenshots/4.4_Settings_GlobalSettings.png)](screenshots/4.4_Settings_GlobalSettings.png)

Global Fail2Ban defaults: `bantime`, `findtime`, `maxretry`, and the `banaction` backend (nftables, firewalld, iptables). When bantime increment is enabled, the escalation behavior can be tuned with `bantime.rndtime`, `bantime.maxtime` (cap for escalating bans), `bantime.factor` (escalation multiplier), and `bantime.overalljails` (count repeat offenses across all jails).

## Contributing

Documentation and deployment guidance in security tooling is never "done", and engineers are not always the fastest at writing it down in docs.

If you see a clearer way to describe installation steps, safer container defaults, better reverse-proxy examples, SELinux improvements, or a more practical demo environment, please contribute. Small improvements (typos, wording, examples) are just as valuable as code changes.

To add a UI language: copy `pkg/web/locales/en.json`, translate all values, save it as `pkg/web/locales/<lang>.json`, and open a pull request. Use a lowercase locale code for `<lang>`, for example `ch`, `ch_de`, `es`, or `pt_br`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

AGPL-3.0. See [LICENSE](LICENSE).
