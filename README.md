# Fail2Ban UI

Fail2Ban UI is a web interface for operating Fail2Ban across one or more Linux hosts. It provides a central place to review bans, search and unban IPs, manage jails and filters, and receive notifications.

The project is maintained by Swissmakers GmbH and released under GPL-3.0.

## What this project does

Fail2Ban UI does not replace Fail2Ban. It connects to existing Fail2Ban instances and adds:

- A Dashboard for active jails and recent ban/unban activity
- Server Manager for adding new fail2ban servers to Fail2ban-UI
- Central search and unban across jails and servers
- Remote editing / creating, of jail/filter configuration (depending on connector)
- Filter debug integration and live log-pattern testing
- Advanced ban actions for recurring offenders e.g. automatically ban on pfSense and Mikrotik, when threshold is reached.
- Optional email alerts with GeoIP/Whois enrichment for selected "alert countries" only.
- Optional OIDC login (Keycloak, Authentik, Pocket-ID)
- Least-privilege, SELinux-aware container deployment (policies provided)
- .. and much more to come.

## Connector types

| Connector | Typical use | Notes |
|---|---|---|
| Local | Fail2Ban runs on the same host as the UI | Uses the Fail2Ban socket and local files |
| SSH | Manage remote Fail2Ban hosts without installing an agent | Uses key-based SSH and remote `fail2ban-client` |
| Agent (technical preview) | Environments where SSH is not desired | Limited functionality; work in progress |

## Quick start (container)

Prerequisites:
- A Linux host with Podman or Docker
- If you manage a local Fail2Ban instance: access to `/etc/fail2ban` and `/var/run/fail2ban` is needed by Fail2ban-UI

Procedure (local connector example):
```bash
podman run -d --name fail2ban-ui --network=host \
  -v /opt/fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /var/log:/var/log:ro \
  swissmakers/fail2ban-ui:latest
````

Verification:

* Open `http://localhost:8080`
* In the UI: Settings → Manage Servers → enable “Local connector” and run “Test connection”

Next steps:

* For Compose, systemd, SELinux, and remote connectors, see the documentation links below.

## Documentation

* Installation: `docs/installation.md`
* Configuration reference (env vars, callback URL/secret, OIDC): `docs/configuration.md`
* Security guidance (recommended deployment posture): `docs/security.md`
* Architecture overview: `docs/architecture.md`
* API reference: `docs/api.md`
* Troubleshooting: `docs/troubleshooting.md`

Existing deployment guides in this repository:

* Container: `deployment/container/README.md`
* systemd: `deployment/systemd/README.md`
* SELinux policies: `deployment/container/SELinux/`

Development / testing stacks:
* OIDC dev stack: `development/oidc/README.md`
* SSH and local connector dev stack: `development/ssh_and_local/README.md`

## Screenshots

A set of screenshots is available in `screenshots/`

### Main Dashboard
![Dashboard](screenshots/0_Dashboard.png)
The main dashboard view showing an overview of all active jails, banned IPs, and real-time statistics. Displays total bans, recent activity, and quick access to key features.

#### Unban IP
![Unban IP](screenshots/0.1_Dashboard_unban_IP.png)
Unbanning a IP addresses directly from the dashboard. Shows the unban confirmation dialog.

### Server Management
![Manage Servers](screenshots/1_Dashboard_Manage_Servers.png)
Server management modal for configuring / adding and managing multiple Fail2Ban instances. Supports local, SSH, and API agent connections.

### Jail / Filter Management
![Manage Jails](screenshots/1.1_Dashboard_Manage_Jails.png)
Overview of all configured jails with their enabled/disabled status. Allows centralized management of jail configurations across multiple servers.

#### Edit Jail Configuration
![Edit Jail](screenshots/1.2_Dashboard_Manage_Jails_Edit.png)
When clicking on "Edit Filter / Jail" the Jail configuration editor is opened. It shows the current filter and jail configuration  with all options to modify the settings, test or add / modify the logpaths, and save changes.

#### Logpath Test
![Logpath Test](screenshots/1.3_Dashboard_Manage_Jails_Edit_Logpathtest.png)
Logpath testing functionality that verifies log file paths and checks if files are accessible. Shows test results with visual indicators (✓/✗) for each log path.

#### Create new Filter
![Create Filter](screenshots/1.4_Dashboard_Manage_Jails_Create_Filter.png)
The first button opens the modal for creating new Fail2Ban filter files. Includes filter configuration editor with syntax highlighting and validation.

#### Create new Jail
![Create Jail](screenshots/1.5_Dashboard_Manage_Jails_Create_Jail.png)
The second button opens the Jail creation modal for setting up new jails. Allows configuration of seperate jails with special parameters, filter selection, with automatic configuration generation.

### Search Functionality
![Search](screenshots/1.6_Dashboard_search.png)
Search for a specific IPs, that where blocked in a specific jail - searches in all active jails. Provides a quick and painless filtering.

### Internal Log Overview
![Log Overview](screenshots/2_Dashboard_Log_Overview.png)
Comprehensive log overview showing ban / unban events, timestamps, and associated jails and recurring offenders. Provides detailed information about past security events.

#### Whois Information
![Whois](screenshots/2.1_Dashboard_Log_Overview_Whois.png)
Whois lookup modal displaying detailed information about banned IP addresses, including geographic location, ISP details, and network information.

#### Ban Logs
![Ban Logs](screenshots/2.2_Dashboard_Log_Overview_BanLogs.png)
Detailed ban log view showing log lines that triggered the ban, timestamps, and context information for each security event.

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
When enabled the Debug console  showing real-time application logs, system messages, and debugging information. Useful for troubleshooting and monitoring without the need to query the container logs manually everytime.

#### Advanced Ban Actions
![Advanced Ban Actions](screenshots/4.2_Settings_AdvancedBanActions.png)
Configuration for advanced ban actions including permanent blocking, firewall integrations (Mikrotik, pfSense, OPNsense), and threshold settings for recurring offenders.

#### Alert Settings
![Alert Settings](screenshots/4.3_Settings_AlertSettings.png)
Email alert configuration with SMTP settings, country-based filtering (blocks from what country to raport), GeoIP provider selection, and alert preferences for bans and unbans.

#### Global Settings
![Global Settings](screenshots/4.4_Settings_GlobalSettings.png)
Global Fail2Ban settings including default bantime, findtime, maxretry, banaction configuration (nftables/firewalld/iptables) and so on.

## Security notes (think before exposing the UI)

* Do not expose the UI directly to the public Internet. Put it behind a reverse proxy, VPN, firewall rules, and/or OIDC.
* SSH connector should use a dedicated service account with minimal sudo permissions and ACLs.

See `docs/security.md` for details.

## Contributing

Documentation and deployment guidance in security tooling is never "done", and engineers are not always the fastest at writing it down in docs.

If you see a clearer way to describe installation steps, safer container defaults, better reverse-proxy examples, SELinux improvements, or a more practical demo environment, please contribute. Small improvements (typos, wording, examples) are just as valuable as code changes.


See `CONTRIBUTING.md` for more info.

## License

GPL-3.0. See `LICENSE`.