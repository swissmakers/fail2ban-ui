# Fail2Ban UI Screenshots

This directory contains screenshots showcasing the features and the interface of Fail2Ban UI.

## Main Dashboard
![Dashboard](0_Dashboard.png)
**Description:** The main dashboard view showing an overview of all active jails, banned IPs, and real-time statistics. Displays total bans, recent activity, and quick access to key features.

## Unban IP
![Unban IP](0.1_Dashboard_unban_IP.png)
**Description:** Unbanning a IP addresses directly from the dashboard. Shows the unban confirmation dialog.

## Server Management
![Manage Servers](1_Dashboard_Manage_Servers.png)
**Description:** Server management interface for configuring / adding and managing multiple Fail2Ban instances. Supports local, SSH, and API agent connections.

## Jail Management
![Manage Jails](1.1_Dashboard_Manage_Jails.png)
**Description:** Overview of all configured jails with their enabled/disabled status. Allows centralized management of jail configurations across multiple servers.

### Edit Jail Configuration
![Edit Jail](1.2_Dashboard_Manage_Jails_Edit.png)
**Description:** When clicking on "Edit Filter / Jail" the Jail configuration editor is opened. It shows the current filter and jail configuration  with all options to modify the settings, test or add / modify the logpaths, and save changes.

### Logpath Test
![Logpath Test](1.3_Dashboard_Manage_Jails_Edit_Logpathtest.png)
**Description:** Logpath testing functionality that verifies log file paths and checks if files are accessible. Shows test results with visual indicators (✓/✗) for each log path.

### Create Filter
![Create Filter](1.4_Dashboard_Manage_Jails_Create_Filter.png)
**Description:** The first button opens the modal for creating new Fail2Ban filter files. Includes filter configuration editor with syntax highlighting and validation.

### Create Jail
![Create Jail](1.5_Dashboard_Manage_Jails_Create_Jail.png)
**Description:** The second button opens the Jail creation modal for setting up new jails. Allows configuration of seperate jails with special parameters, filter selection, with automatic configuration generation.

## Search Functionality
![Search](1.6_Dashboard_search.png)
**Description:** Search for a specific IPs, that where blocked in a specific jail - searches in all active jails. Provides a quick and painless filtering.

## Internal Log Overview
![Log Overview](2_Dashboard_Log_Overview.png)
**Description:** Comprehensive log overview showing ban / unban events, timestamps, and associated jails and recurring offenders. Provides detailed information about past security events.

### Whois Information
![Whois](2.1_Dashboard_Log_Overview_Whois.png)
**Description:** Whois lookup modal displaying detailed information about banned IP addresses, including geographic location, ISP details, and network information.

### Ban Logs
![Ban Logs](2.2_Dashboard_Log_Overview_BanLogs.png)
**Description:** Detailed ban log view showing log lines that triggered the ban, timestamps, and context information for each security event.

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
**Description:** When enabled the Debug console  showing real-time application logs, system messages, and debugging information. Useful for troubleshooting and monitoring without the need to query the container logs manually everytime.

### Advanced Ban Actions
![Advanced Ban Actions](4.2_Settings_AdvancedBanActions.png)
**Description:** Configuration for advanced ban actions including permanent blocking, firewall integrations (Mikrotik, pfSense, OPNsense), and threshold settings for recurring offenders.

### Alert Settings
![Alert Settings](4.3_Settings_AlertSettings.png)
**Description:** Email alert configuration with SMTP settings, country-based filtering (blocks from what country to raport), GeoIP provider selection, and alert preferences for bans and unbans.

### Global Settings
![Global Settings](4.4_Settings_GlobalSettings.png)
**Description:** Global Fail2Ban settings including default bantime, findtime, maxretry, banaction configuration (nftables/firewalld/iptables) and so on.
