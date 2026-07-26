# Fail2Ban UI Screenshots

This directory contains screenshots showcasing the features and the interface of Fail2Ban UI.

## Main Dashboard
![Dashboard](0_Dashboard.png)
**Description:** The main dashboard view showing an overview of all active jails, banned IPs, and real-time statistics. Displays total bans, recent activity, and quick access to key features.

## Unban IP
![Unban IP](0.1_Dashboard_unban_IP.png)
**Description:** Unban an IP address directly from the dashboard. A confirmation dialog shows the affected jail before the unban runs.

## Server Management
![Manage Servers](1_Dashboard_Manage_Servers.png)
**Description:** Server management interface for configuring / adding and managing multiple Fail2Ban instances. Supports local, SSH, and API agent connections.

## Jail Management
![Manage Jails](1.1_Dashboard_Manage_Jails.png)
**Description:** Overview of all configured jails with their enabled/disabled status. Allows centralized management of jail configurations across multiple servers.

### Edit Jail Configuration
![Edit Jail](1.2_Dashboard_Manage_Jails_Edit.png)
**Description:** Clicking **Edit Filter / Jail** opens the configuration editor. Edit the jail and filter settings, add or change log paths and test them, then save - the change is pushed to the managed host and Fail2Ban is reloaded.

### Logpath Test
![Logpath Test](1.3_Dashboard_Manage_Jails_Edit_Logpathtest.png)
**Description:** Logpath testing resolves the configured paths, including wildcards and Fail2Ban variables, and checks whether matching files exist. Each path is reported as ✓ found, ✗ not found, or ⚠ cannot verify.

### Create Filter
![Create Filter](1.4_Dashboard_Manage_Jails_Create_Filter.png)
**Description:** The first button opens the modal for creating new Fail2Ban filter files. Includes filter configuration editor with syntax highlighting and validation.

### Create Jail
![Create Jail](1.5_Dashboard_Manage_Jails_Create_Jail.png)
**Description:** The second button opens the jail creation modal for setting up new jails. It supports separate jail definitions with custom parameters and filter selection.

## Search Functionality
![Search](1.6_Dashboard_search.png)
**Description:** Search for an IP address across all active jails of every configured server. The result lists each jail that currently bans the address, so it can be unbanned in the right place.

## Internal Log Overview
![Log Overview](2_Dashboard_Log_Overview.png)
**Description:** Comprehensive log overview showing ban / unban events, timestamps, and associated jails and recurring offenders. Provides detailed information about past security events.

### Whois Information
![Whois](2.1_Dashboard_Log_Overview_Whois.png)
**Description:** Whois lookup modal displaying detailed information about banned IP addresses, including geographic location, ISP details, and network information.

### Ban Logs
![Ban Logs](2.2_Dashboard_Log_Overview_BanLogs.png)
**Description:** Detailed ban log view showing log lines that triggered the ban, timestamps, and context information for each security event.

### Ban Insights
![Ban Insights](2.3_Dashboard_Log_Overview_BanInsights.png)
**Description:** SIEM-like analysis without a full SIEM -> a ban/unban timeline (drag to zoom, presets from 8 hours to 30 days, custom range up to 12 months) makes spikes and attack patterns visible. Pin two spikes as Incident A and B to list the IPs present in both -> repeat attackers, not false positives and ban them permanently to the recurring-offenders list, or select a time range where no legitimate user is active and block every IP in it with one click.

## Filter Debugging
![Filter Debug](3_Filter_Debug.png)
**Description:** Filter debugging interface for testing Fail2Ban filter regex patterns against log lines. Helps validate filter configurations before deployment.

### Filter Test Results
![Filter Test Results](3.1_Filter_Debug_Testresult.png)
**Description:** Results from filter testing showing matched lines, regex performance, and validation feedback. Displays which log lines match the filter pattern.

## Settings
![Settings](4_Settings.png)
**Description:** Main settings page with sections for different configuration categories including general settings, advanced ban actions, alert settings, and global fail2ban settings.

### Debug Console
![Debug Console](4.1_Settings_DebugConsole.png)
**Description:** When enabled, the debug console streams the live application log into the browser -> useful for troubleshooting without querying the container logs manually. Leave it disabled in normal operation.

### Advanced Ban Actions
![Advanced Ban Actions](4.2_Settings_AdvancedBanActions.png)
**Description:** Configuration for advanced ban actions including permanent blocking, firewall integrations (Mikrotik, pfSense, OPNsense), and threshold settings for recurring offenders.

### Alert Settings
![Alert Settings](4.3_Settings_AlertSettings.png)
**Description:** Alert provider configuration. One of three mutually exclusive providers is active at a time - Email (SMTP), Webhook, or Elasticsearch with per-event toggles for bans and unbans, country-based filtering (which countries to report on), GeoIP provider selection, the maximum number of log lines per alert, and the event retention window. See [docs/alert-providers.md](../docs/alert-providers.md).

### Global Settings
![Global Settings](4.4_Settings_GlobalSettings.png)
**Description:** Global Fail2Ban defaults: `bantime`, `findtime`, `maxretry`, `ignoreip`, and the `banaction` backend (nftables, firewalld, iptables). When bantime increment is enabled, the escalation can be tuned with `bantime.rndtime`, `bantime.maxtime`, `bantime.factor`, and `bantime.overalljails`.

## Example Alert Email
**Description:** [`Example_block_email.pdf`](Example_block_email.pdf) - a rendered example of the Email (SMTP) ban alert, for reference when evaluating the modern template.
