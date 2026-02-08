// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// SMTPSettings holds the SMTP server configuration for sending alert emails
type SMTPSettings struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	From               string `json:"from"`
	UseTLS             bool   `json:"useTLS"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	AuthMethod         string `json:"authMethod"`
}

// AppSettings holds the main UI settings and Fail2ban configuration
type AppSettings struct {
	Language        string                `json:"language"`
	Port            int                   `json:"port"`
	Debug           bool                  `json:"debug"`
	RestartNeeded   bool                  `json:"restartNeeded"`
	AlertCountries  []string              `json:"alertCountries"`
	SMTP            SMTPSettings          `json:"smtp"`
	CallbackURL     string                `json:"callbackUrl"`
	CallbackSecret  string                `json:"callbackSecret"`
	AdvancedActions AdvancedActionsConfig `json:"advancedActions"`

	Servers []Fail2banServer `json:"servers"`

	// Fail2Ban [DEFAULT] section values from jail.local
	BantimeIncrement  bool     `json:"bantimeIncrement"`
	DefaultJailEnable bool     `json:"defaultJailEnable"`
	IgnoreIPs         []string `json:"ignoreips"` // Changed from string to []string for individual IP management
	Bantime           string   `json:"bantime"`
	Findtime          string   `json:"findtime"`
	Maxretry          int      `json:"maxretry"`
	Destemail         string   `json:"destemail"`
	Banaction         string   `json:"banaction"`         // Default banning action
	BanactionAllports string   `json:"banactionAllports"` // Allports banning action
	Chain             string   `json:"chain"`             // Default iptables/nftables chain (INPUT, DOCKER-USER, FORWARD)
	BantimeRndtime    string   `json:"bantimeRndtime"`    // Optional: bantime.rndtime in seconds (e.g. 2048) for bantime increment formula
	//Sender           string `json:"sender"`

	// GeoIP and Whois settings
	GeoIPProvider     string `json:"geoipProvider"`     // "maxmind" or "builtin"
	GeoIPDatabasePath string `json:"geoipDatabasePath"` // Path to MaxMind database (optional)
	MaxLogLines       int    `json:"maxLogLines"`       // Maximum log lines to include (default: 50)

	// Email alert preferences
	EmailAlertsForBans   bool `json:"emailAlertsForBans"`   // Enable email alerts for ban events (default: true)
	EmailAlertsForUnbans bool `json:"emailAlertsForUnbans"` // Enable email alerts for unban events (default: false)

	// Console output preferences
	ConsoleOutput bool `json:"consoleOutput"` // Enable console output in web UI (default: false)
}

// OIDCConfig holds OIDC authentication configuration
type OIDCConfig struct {
	Enabled       bool     `json:"enabled"`
	Provider      string   `json:"provider"` // keycloak, authentik, pocketid
	IssuerURL     string   `json:"issuerURL"`
	ClientID      string   `json:"clientID"`
	ClientSecret  string   `json:"clientSecret"`
	RedirectURL   string   `json:"redirectURL"`
	Scopes        []string `json:"scopes"`        // Default: ["openid", "profile", "email"]
	SessionSecret string   `json:"sessionSecret"` // For session encryption
	SessionMaxAge int      `json:"sessionMaxAge"` // Session timeout in seconds
	SkipVerify    bool     `json:"skipVerify"`    // Skip TLS verification (dev only)
	UsernameClaim string   `json:"usernameClaim"` // Claim to use as username
	LogoutURL     string   `json:"logoutURL"`     // Provider logout URL (optional)
	SkipLoginPage bool     `json:"skipLoginPage"` // Skip login page and redirect directly to OIDC provider (default: false)
}

type AdvancedActionsConfig struct {
	Enabled     bool                        `json:"enabled"`
	Threshold   int                         `json:"threshold"`
	Integration string                      `json:"integration"`
	Mikrotik    MikrotikIntegrationSettings `json:"mikrotik"`
	PfSense     PfSenseIntegrationSettings  `json:"pfSense"`
	OPNsense    OPNsenseIntegrationSettings `json:"opnsense"`
}

type MikrotikIntegrationSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SSHKeyPath  string `json:"sshKeyPath"`
	AddressList string `json:"addressList"`
}

type PfSenseIntegrationSettings struct {
	BaseURL       string `json:"baseUrl"`
	APIToken      string `json:"apiToken"`
	APISecret     string `json:"apiSecret"`
	Alias         string `json:"alias"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

type OPNsenseIntegrationSettings struct {
	BaseURL       string `json:"baseUrl"`
	APIKey        string `json:"apiKey"`
	APISecret     string `json:"apiSecret"`
	Alias         string `json:"alias"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

func defaultAdvancedActionsConfig() AdvancedActionsConfig {
	return AdvancedActionsConfig{
		Enabled:     false,
		Threshold:   5,
		Integration: "",
		Mikrotik: MikrotikIntegrationSettings{
			Port:        22,
			AddressList: "fail2ban-permanent",
		},
	}
}

func normalizeAdvancedActionsConfig(cfg AdvancedActionsConfig) AdvancedActionsConfig {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.Mikrotik.Port <= 0 {
		cfg.Mikrotik.Port = 22
	}
	if cfg.Mikrotik.AddressList == "" {
		cfg.Mikrotik.AddressList = "fail2ban-permanent"
	}
	return cfg
}

// init paths to key-files
const (
	settingsFile              = "fail2ban-ui-settings.json" // this file is created, relatively to where the app was started
	jailFile                  = "/etc/fail2ban/jail.local"
	actionFile                = "/etc/fail2ban/action.d/ui-custom-action.conf"
	actionCallbackPlaceholder = "__CALLBACK_URL__"
	actionServerIDPlaceholder = "__SERVER_ID__"
	actionSecretPlaceholder   = "__CALLBACK_SECRET__"
	actionCurlInsecureFlag    = "__CURL_INSECURE_FLAG__"
)

// jailLocalBanner is the standard banner for jail.local files
const jailLocalBanner = `################################################################################
# Fail2Ban-UI Managed Configuration
# 
# WARNING: This file is automatically managed by Fail2Ban-UI.
# DO NOT EDIT THIS FILE MANUALLY - your changes will be overwritten.
#
# This file overrides settings from /etc/fail2ban/jail.conf
# Custom jail configurations should be placed in /etc/fail2ban/jail.d/
################################################################################

`

// JailLocalBanner returns the standard banner for jail.local files
func JailLocalBanner() string {
	return jailLocalBanner
}

const fail2banActionTemplate = `[Definition]

# Bypass ban/unban for restored tickets
norestored = 1

# Option: actionban
# This executes a cURL request to notify our API when an IP is banned.

actionban = /usr/bin/curl__CURL_INSECURE_FLAG__ -X POST __CALLBACK_URL__/api/ban \
     -H "Content-Type: application/json" \
     -H "X-Callback-Secret: __CALLBACK_SECRET__" \
     -d "$(jq -n --arg serverId '__SERVER_ID__' \
                 --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 --arg failures '<failures>' \
                 --arg logs "$(tac <logpath> | grep <grepopts> -wF <ip>)" \
                 '{serverId: $serverId, ip: $ip, jail: $jail, hostname: $hostname, failures: $failures, logs: $logs}')"

# Option: actionunban
# This executes a cURL request to notify our API when an IP is unbanned.

actionunban = /usr/bin/curl__CURL_INSECURE_FLAG__ -X POST __CALLBACK_URL__/api/unban \
     -H "Content-Type: application/json" \
     -H "X-Callback-Secret: __CALLBACK_SECRET__" \
     -d "$(jq -n --arg serverId '__SERVER_ID__' \
                 --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 '{serverId: $serverId, ip: $ip, jail: $jail, hostname: $hostname}')"

[Init]

# Default name of the chain
name = default

# Path to log files containing relevant lines for the abuser IP
logpath = /dev/null

# Number of log lines to include in the callback
grepmax = 200
grepopts = -m <grepmax>`

// in-memory copy of settings
var (
	currentSettings AppSettings
	settingsLock    sync.RWMutex
)

var (
	errSettingsNotFound = errors.New("settings not found")
	backgroundCtx       = context.Background()
)

// Fail2banServer represents a Fail2ban instance the UI can manage.
type Fail2banServer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"` // local, ssh, agent
	Host          string    `json:"host,omitempty"`
	Port          int       `json:"port,omitempty"`
	SocketPath    string    `json:"socketPath,omitempty"`
	LogPath       string    `json:"logPath,omitempty"`
	SSHUser       string    `json:"sshUser,omitempty"`
	SSHKeyPath    string    `json:"sshKeyPath,omitempty"`
	AgentURL      string    `json:"agentUrl,omitempty"`
	AgentSecret   string    `json:"agentSecret,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	IsDefault     bool      `json:"isDefault"`
	Enabled       bool      `json:"enabled"`
	RestartNeeded bool      `json:"restartNeeded"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`

	enabledSet bool
}

func (s *Fail2banServer) UnmarshalJSON(data []byte) error {
	type Alias Fail2banServer
	aux := &struct {
		Enabled *bool `json:"enabled"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Enabled != nil {
		s.Enabled = *aux.Enabled
		s.enabledSet = true
	} else {
		s.enabledSet = false
	}
	return nil
}

func init() {
	if err := storage.Init(""); err != nil {
		panic(fmt.Sprintf("failed to initialise storage: %v", err))
	}

	if err := loadSettingsFromStorage(); err != nil {
		if !errors.Is(err, errSettingsNotFound) {
			fmt.Println("Error loading settings from storage:", err)
		}

		if err := migrateLegacySettings(); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Println("Error migrating legacy settings:", err)
			}
			fmt.Println("App settings not found, initializing from jail.local (if exist)")
			if err := initializeFromJailFile(); err != nil {
				fmt.Println("Error reading jail.local:", err)
			}
			setDefaults()
			fmt.Println("Initialized with defaults.")
		}

		if err := persistAll(); err != nil {
			fmt.Println("Failed to persist settings:", err)
		}
	} else {
		if err := persistAll(); err != nil {
			fmt.Println("Failed to persist settings:", err)
		}
	}
}

func loadSettingsFromStorage() error {
	appRec, found, err := storage.GetAppSettings(backgroundCtx)
	if err != nil {
		return err
	}
	serverRecs, err := storage.ListServers(backgroundCtx)
	if err != nil {
		return err
	}
	if !found {
		return errSettingsNotFound
	}

	settingsLock.Lock()
	defer settingsLock.Unlock()

	applyAppSettingsRecordLocked(appRec)
	applyServerRecordsLocked(serverRecs)
	setDefaultsLocked()
	return nil
}

func migrateLegacySettings() error {
	data, err := os.ReadFile(settingsFile)
	if err != nil {
		return err
	}

	var legacy AppSettings
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	settingsLock.Lock()
	currentSettings = legacy
	settingsLock.Unlock()

	return nil
}

func persistAll() error {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	setDefaultsLocked()
	return persistAllLocked()
}

func persistAllLocked() error {
	if err := persistAppSettingsLocked(); err != nil {
		return err
	}
	return persistServersLocked()
}

func persistAppSettingsLocked() error {
	rec, err := toAppSettingsRecordLocked()
	if err != nil {
		return err
	}
	return storage.SaveAppSettings(backgroundCtx, rec)
}

func persistServersLocked() error {
	records, err := toServerRecordsLocked()
	if err != nil {
		return err
	}
	return storage.ReplaceServers(backgroundCtx, records)
}

func applyAppSettingsRecordLocked(rec storage.AppSettingsRecord) {
	currentSettings.Language = rec.Language
	currentSettings.Port = rec.Port
	currentSettings.Debug = rec.Debug
	currentSettings.CallbackURL = rec.CallbackURL
	currentSettings.RestartNeeded = rec.RestartNeeded
	currentSettings.BantimeIncrement = rec.BantimeIncrement
	currentSettings.DefaultJailEnable = rec.DefaultJailEnable
	// Convert IgnoreIP string to array (backward compatibility)
	if rec.IgnoreIP != "" {
		currentSettings.IgnoreIPs = strings.Fields(rec.IgnoreIP)
	} else {
		currentSettings.IgnoreIPs = []string{}
	}
	currentSettings.Bantime = rec.Bantime
	currentSettings.Findtime = rec.Findtime
	currentSettings.Maxretry = rec.MaxRetry
	currentSettings.Destemail = rec.DestEmail
	currentSettings.Banaction = rec.Banaction
	currentSettings.BanactionAllports = rec.BanactionAllports
	if rec.Chain != "" {
		currentSettings.Chain = rec.Chain
	} else {
		currentSettings.Chain = "INPUT"
	}
	currentSettings.BantimeRndtime = rec.BantimeRndtime
	currentSettings.SMTP = SMTPSettings{
		Host:               rec.SMTPHost,
		Port:               rec.SMTPPort,
		Username:           rec.SMTPUsername,
		Password:           rec.SMTPPassword,
		From:               rec.SMTPFrom,
		UseTLS:             rec.SMTPUseTLS,
		InsecureSkipVerify: rec.SMTPInsecureSkipVerify,
		AuthMethod:         rec.SMTPAuthMethod,
	}

	if rec.AlertCountriesJSON != "" {
		var countries []string
		if err := json.Unmarshal([]byte(rec.AlertCountriesJSON), &countries); err == nil {
			currentSettings.AlertCountries = countries
		}
	}
	if rec.AdvancedActionsJSON != "" {
		var adv AdvancedActionsConfig
		if err := json.Unmarshal([]byte(rec.AdvancedActionsJSON), &adv); err == nil {
			currentSettings.AdvancedActions = adv
		}
	}
	currentSettings.GeoIPProvider = rec.GeoIPProvider
	currentSettings.GeoIPDatabasePath = rec.GeoIPDatabasePath
	currentSettings.MaxLogLines = rec.MaxLogLines
	currentSettings.CallbackSecret = rec.CallbackSecret
	currentSettings.EmailAlertsForBans = rec.EmailAlertsForBans
	currentSettings.EmailAlertsForUnbans = rec.EmailAlertsForUnbans
	currentSettings.ConsoleOutput = rec.ConsoleOutput
}

func applyServerRecordsLocked(records []storage.ServerRecord) {
	servers := make([]Fail2banServer, 0, len(records))
	for _, rec := range records {
		var tags []string
		if rec.TagsJSON != "" {
			_ = json.Unmarshal([]byte(rec.TagsJSON), &tags)
		}
		server := Fail2banServer{
			ID:            rec.ID,
			Name:          rec.Name,
			Type:          rec.Type,
			Host:          rec.Host,
			Port:          rec.Port,
			SocketPath:    rec.SocketPath,
			LogPath:       rec.LogPath,
			SSHUser:       rec.SSHUser,
			SSHKeyPath:    rec.SSHKeyPath,
			AgentURL:      rec.AgentURL,
			AgentSecret:   rec.AgentSecret,
			Hostname:      rec.Hostname,
			Tags:          tags,
			IsDefault:     rec.IsDefault,
			Enabled:       rec.Enabled,
			RestartNeeded: rec.NeedsRestart,
			CreatedAt:     rec.CreatedAt,
			UpdatedAt:     rec.UpdatedAt,
			enabledSet:    true,
		}
		servers = append(servers, server)
	}
	currentSettings.Servers = servers
}

func toAppSettingsRecordLocked() (storage.AppSettingsRecord, error) {
	countries := currentSettings.AlertCountries
	if countries == nil {
		countries = []string{}
	}
	countryBytes, err := json.Marshal(countries)
	if err != nil {
		return storage.AppSettingsRecord{}, err
	}

	advancedBytes, err := json.Marshal(currentSettings.AdvancedActions)
	if err != nil {
		return storage.AppSettingsRecord{}, err
	}

	return storage.AppSettingsRecord{
		// Basic app settings
		Language:      currentSettings.Language,
		Port:          currentSettings.Port,
		Debug:         currentSettings.Debug,
		RestartNeeded: currentSettings.RestartNeeded,
		// Callback settings
		CallbackURL:    currentSettings.CallbackURL,
		CallbackSecret: currentSettings.CallbackSecret,
		// Alert settings
		AlertCountriesJSON:   string(countryBytes),
		EmailAlertsForBans:   currentSettings.EmailAlertsForBans,
		EmailAlertsForUnbans: currentSettings.EmailAlertsForUnbans,
		// SMTP settings
		SMTPHost:               currentSettings.SMTP.Host,
		SMTPPort:               currentSettings.SMTP.Port,
		SMTPUsername:           currentSettings.SMTP.Username,
		SMTPPassword:           currentSettings.SMTP.Password,
		SMTPFrom:               currentSettings.SMTP.From,
		SMTPUseTLS:             currentSettings.SMTP.UseTLS,
		SMTPInsecureSkipVerify: currentSettings.SMTP.InsecureSkipVerify,
		SMTPAuthMethod:         currentSettings.SMTP.AuthMethod,
		// Fail2Ban DEFAULT settings
		BantimeIncrement:  currentSettings.BantimeIncrement,
		DefaultJailEnable: currentSettings.DefaultJailEnable,
		// Convert IgnoreIPs array to space-separated string for storage
		IgnoreIP:          strings.Join(currentSettings.IgnoreIPs, " "),
		Bantime:           currentSettings.Bantime,
		Findtime:          currentSettings.Findtime,
		MaxRetry:          currentSettings.Maxretry,
		DestEmail:         currentSettings.Destemail,
		Banaction:         currentSettings.Banaction,
		BanactionAllports: currentSettings.BanactionAllports,
		Chain:             currentSettings.Chain,
		BantimeRndtime:    currentSettings.BantimeRndtime,
		// Advanced features
		AdvancedActionsJSON: string(advancedBytes),
		GeoIPProvider:       currentSettings.GeoIPProvider,
		GeoIPDatabasePath:   currentSettings.GeoIPDatabasePath,
		MaxLogLines:         currentSettings.MaxLogLines,
		// Console output settings
		ConsoleOutput: currentSettings.ConsoleOutput,
	}, nil
}

func toServerRecordsLocked() ([]storage.ServerRecord, error) {
	records := make([]storage.ServerRecord, 0, len(currentSettings.Servers))
	for _, srv := range currentSettings.Servers {
		tags := srv.Tags
		if tags == nil {
			tags = []string{}
		}
		tagBytes, err := json.Marshal(tags)
		if err != nil {
			return nil, err
		}
		createdAt := srv.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		updatedAt := srv.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}
		records = append(records, storage.ServerRecord{
			ID:           srv.ID,
			Name:         srv.Name,
			Type:         srv.Type,
			Host:         srv.Host,
			Port:         srv.Port,
			SocketPath:   srv.SocketPath,
			LogPath:      srv.LogPath,
			SSHUser:      srv.SSHUser,
			SSHKeyPath:   srv.SSHKeyPath,
			AgentURL:     srv.AgentURL,
			AgentSecret:  srv.AgentSecret,
			Hostname:     srv.Hostname,
			TagsJSON:     string(tagBytes),
			IsDefault:    srv.IsDefault,
			Enabled:      srv.Enabled,
			NeedsRestart: srv.RestartNeeded,
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
		})
	}
	return records, nil
}

// setDefaults populates default values in currentSettings
func setDefaults() {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	setDefaultsLocked()
}

func setDefaultsLocked() {
	if currentSettings.Language == "" {
		currentSettings.Language = "en"
	}

	// Set email alert defaults
	if !currentSettings.EmailAlertsForBans && !currentSettings.EmailAlertsForUnbans {
		// Check if it is uninitialized by checking if we have other initialized values
		// If we have a callback secret or port set, it means we've loaded from storage, so we don't override
		if currentSettings.CallbackSecret == "" && currentSettings.Port == 0 {
			// Uninitialized so we set defaults
			currentSettings.EmailAlertsForBans = true
			currentSettings.EmailAlertsForUnbans = false
		}
	}

	// Check for PORT environment variable first - it always takes priority
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if port, err := strconv.Atoi(portEnv); err == nil && port > 0 && port <= 65535 {
			currentSettings.Port = port
		} else if currentSettings.Port == 0 {
			currentSettings.Port = 8080
		}
	} else if currentSettings.Port == 0 {
		currentSettings.Port = 8080
	}
	// Auto-update callback URL if it's empty or still using the old default localhost pattern
	if currentSettings.CallbackURL == "" {
		currentSettings.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d", currentSettings.Port)
	} else {
		// If callback URL matches the old default pattern, update it to match the current port
		oldPattern := regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)
		if oldPattern.MatchString(currentSettings.CallbackURL) {
			currentSettings.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d", currentSettings.Port)
		}
	}
	// Generate callback secret if not set (only generate once, never regenerate)
	if currentSettings.CallbackSecret == "" {
		currentSettings.CallbackSecret = generateCallbackSecret()
	}
	if currentSettings.AlertCountries == nil {
		currentSettings.AlertCountries = []string{"ALL"}
	}
	if currentSettings.Bantime == "" {
		currentSettings.Bantime = "48h"
	}
	if currentSettings.Findtime == "" {
		currentSettings.Findtime = "30m"
	}
	if currentSettings.Maxretry == 0 {
		currentSettings.Maxretry = 3
	}
	if currentSettings.Destemail == "" {
		currentSettings.Destemail = "alerts@example.com"
	}
	if currentSettings.SMTP.Host == "" {
		currentSettings.SMTP.Host = "smtp.office365.com"
	}
	if currentSettings.SMTP.Port == 0 {
		currentSettings.SMTP.Port = 587
	}
	if currentSettings.SMTP.Username == "" {
		currentSettings.SMTP.Username = "noreply@swissmakers.ch"
	}
	if currentSettings.SMTP.Password == "" {
		currentSettings.SMTP.Password = "password"
	}
	if currentSettings.SMTP.From == "" {
		currentSettings.SMTP.From = "noreply@swissmakers.ch"
	}
	if !currentSettings.SMTP.UseTLS {
		currentSettings.SMTP.UseTLS = true
	}
	if currentSettings.SMTP.AuthMethod == "" {
		currentSettings.SMTP.AuthMethod = "auto"
	}
	if len(currentSettings.IgnoreIPs) == 0 {
		currentSettings.IgnoreIPs = []string{"127.0.0.1/8", "::1"}
	}
	if currentSettings.Banaction == "" {
		currentSettings.Banaction = "nftables-multiport"
	}
	if currentSettings.BanactionAllports == "" {
		currentSettings.BanactionAllports = "nftables-allports"
	}
	if currentSettings.Chain == "" {
		currentSettings.Chain = "INPUT"
	}
	if currentSettings.GeoIPProvider == "" {
		currentSettings.GeoIPProvider = "builtin"
	}
	if currentSettings.GeoIPDatabasePath == "" {
		currentSettings.GeoIPDatabasePath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
	}
	if currentSettings.MaxLogLines == 0 {
		currentSettings.MaxLogLines = 50
	}

	if (currentSettings.AdvancedActions == AdvancedActionsConfig{}) {
		currentSettings.AdvancedActions = defaultAdvancedActionsConfig()
	}
	currentSettings.AdvancedActions = normalizeAdvancedActionsConfig(currentSettings.AdvancedActions)

	normalizeServersLocked()
}

// initializeFromJailFile reads Fail2ban jail.local and merges its settings into currentSettings.
func initializeFromJailFile() error {
	file, err := os.Open(jailFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^\s*(?P<key>[a-zA-Z0-9_]+)\s*=\s*(?P<value>.+)$`)

	settings := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); matches != nil {
			key := strings.ToLower(matches[1])
			value := matches[2]
			settings[key] = value
		}
	}

	settingsLock.Lock()
	defer settingsLock.Unlock()

	if val, ok := settings["bantime"]; ok {
		currentSettings.Bantime = val
	}
	if val, ok := settings["findtime"]; ok {
		currentSettings.Findtime = val
	}
	if val, ok := settings["maxretry"]; ok {
		if maxRetry, err := strconv.Atoi(val); err == nil {
			currentSettings.Maxretry = maxRetry
		}
	}
	if val, ok := settings["ignoreip"]; ok {
		// Convert space-separated string to array
		if val != "" {
			currentSettings.IgnoreIPs = strings.Fields(val)
		} else {
			currentSettings.IgnoreIPs = []string{}
		}
	}
	if val, ok := settings["banaction"]; ok {
		currentSettings.Banaction = val
	}
	if val, ok := settings["banaction_allports"]; ok {
		currentSettings.BanactionAllports = val
	}
	if val, ok := settings["chain"]; ok && val != "" {
		currentSettings.Chain = val
	}
	if val, ok := settings["bantime.rndtime"]; ok && val != "" {
		currentSettings.BantimeRndtime = val
	}
	/*if val, ok := settings["destemail"]; ok {
		currentSettings.Destemail = val
	}*/

	return nil
}

func normalizeServersLocked() {
	now := time.Now().UTC()
	if len(currentSettings.Servers) == 0 {
		hostname, _ := os.Hostname()
		currentSettings.Servers = []Fail2banServer{{
			ID:         "local",
			Name:       "Fail2ban",
			Type:       "local",
			SocketPath: "/var/run/fail2ban/fail2ban.sock",
			LogPath:    "/var/log/fail2ban.log",
			Hostname:   hostname,
			IsDefault:  false,
			Enabled:    false,
			CreatedAt:  now,
			UpdatedAt:  now,
			enabledSet: true,
		}}
		return
	}

	hasDefault := false
	for idx := range currentSettings.Servers {
		server := &currentSettings.Servers[idx]
		if server.ID == "" {
			server.ID = generateServerID()
		}
		if server.Name == "" {
			server.Name = "Fail2ban Server " + server.ID
		}
		if server.Type == "" {
			server.Type = "local"
		}
		if server.CreatedAt.IsZero() {
			server.CreatedAt = now
		}
		if server.UpdatedAt.IsZero() {
			server.UpdatedAt = now
		}
		if server.Type == "local" && server.SocketPath == "" {
			server.SocketPath = "/var/run/fail2ban/fail2ban.sock"
		}
		if server.Type == "local" && server.LogPath == "" {
			server.LogPath = "/var/log/fail2ban.log"
		}
		if !server.enabledSet {
			if server.Type == "local" {
				server.Enabled = false
			} else {
				server.Enabled = true
			}
		}
		server.enabledSet = true
		if !server.Enabled {
			server.RestartNeeded = false
		}
		if server.IsDefault && !server.Enabled {
			server.IsDefault = false
		}
		if server.IsDefault && server.Enabled {
			hasDefault = true
		}
	}

	if !hasDefault {
		for idx := range currentSettings.Servers {
			if currentSettings.Servers[idx].Enabled {
				currentSettings.Servers[idx].IsDefault = true
				hasDefault = true
				break
			}
		}
	}

	sort.SliceStable(currentSettings.Servers, func(i, j int) bool {
		return currentSettings.Servers[i].CreatedAt.Before(currentSettings.Servers[j].CreatedAt)
	})

	updateGlobalRestartFlagLocked()
}

func generateServerID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("srv-%d", time.Now().UnixNano())
	}
	return "srv-" + hex.EncodeToString(b[:])
}

// ensureFail2banActionFiles writes the local action files if Fail2ban is present.
func ensureFail2banActionFiles(callbackURL, serverID string) error {
	DebugLog("----------------------------")
	DebugLog("ensureFail2banActionFiles called (settings.go)")

	if _, err := os.Stat(filepath.Dir(jailFile)); os.IsNotExist(err) {
		return nil
	}

	// Ensure jail.local has proper structure (banner, DEFAULT, action_mwlg, action override)
	if err := ensureJailLocalStructure(); err != nil {
		return err
	}
	return writeFail2banAction(callbackURL, serverID)
}

// EnsureJailLocalStructure creates or updates jail.local with proper structure:
// This is exported so connectors can call it.
func EnsureJailLocalStructure() error {
	return ensureJailLocalStructure()
}

// ensureJailLocalStructure creates or updates jail.local with proper structure:
// 1. Banner at top warning users not to edit manually
// 2. [DEFAULT] section with current UI settings
// 3. action_mwlg configuration
// 4. action = %(action_mwlg)s at the end
func ensureJailLocalStructure() error {
	DebugLog("Running ensureJailLocalStructure()") // entry point

	// Check if /etc/fail2ban directory exists (fail2ban must be installed)
	if _, err := os.Stat(filepath.Dir(jailFile)); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban is not installed: /etc/fail2ban directory does not exist. Please install fail2ban package first")
	}

	// Get current settings
	settings := GetSettings()

	// Read existing jail.local content if it exists
	var existingContent string
	if content, err := os.ReadFile(jailFile); err == nil {
		existingContent = string(content)
	}

	// Check if file already has our full banner (indicating it's already properly structured)
	// Check for the complete banner pattern with hash line separators
	hasFullBanner := strings.Contains(existingContent, "################################################################################") &&
		strings.Contains(existingContent, "Fail2Ban-UI Managed Configuration") &&
		strings.Contains(existingContent, "DO NOT EDIT THIS FILE MANUALLY")
	hasActionMwlg := strings.Contains(existingContent, "action_mwlg") && strings.Contains(existingContent, "ui-custom-action")
	hasActionOverride := strings.Contains(existingContent, "action = %(action_mwlg)s")

	// If file is already properly structured, just ensure DEFAULT section is up to date
	if hasFullBanner && hasActionMwlg && hasActionOverride {
		DebugLog("jail.local already has proper structure, updating DEFAULT section if needed")
		// Update DEFAULT section values without changing structure
		return updateJailLocalDefaultSection(settings)
	}

	// Use the standard banner
	banner := jailLocalBanner

	// Build [DEFAULT] section
	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banaction := settings.Banaction
	if banaction == "" {
		banaction = "nftables-multiport"
	}
	banactionAllports := settings.BanactionAllports
	if banactionAllports == "" {
		banactionAllports = "nftables-allports"
	}
	chain := settings.Chain
	if chain == "" {
		chain = "INPUT"
	}
	defaultSection := fmt.Sprintf(`[DEFAULT]
enabled = %t
bantime.increment = %t
ignoreip = %s
bantime = %s
findtime = %s
maxretry = %d
banaction = %s
banaction_allports = %s
chain = %s

`, settings.DefaultJailEnable, settings.BantimeIncrement, ignoreIPStr, settings.Bantime, settings.Findtime, settings.Maxretry, banaction, banactionAllports, chain)
	if settings.BantimeRndtime != "" {
		defaultSection += fmt.Sprintf("bantime.rndtime = %s\n", settings.BantimeRndtime)
	}
	defaultSection += "\n"

	// Build action_mwlg configuration
	// Note: action_mwlg depends on action_ which depends on banaction (now defined above)
	// The multi-line format uses indentation for continuation
	// ui-custom-action only needs logpath and chain
	actionMwlgConfig := `# Custom Fail2Ban action for UI callbacks
action_mwlg = %(action_)s
             ui-custom-action[logpath="%(logpath)s", chain="%(chain)s"]

`

	// Build action override (at the end as per user requirements)
	actionOverride := `# Custom Fail2Ban action applied by fail2ban-ui
action = %(action_mwlg)s
`

	// Combine all parts
	newContent := banner + defaultSection + actionMwlgConfig + actionOverride

	// Write the new content
	err := os.WriteFile(jailFile, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write jail.local: %v", err)
	}

	DebugLog("Created/updated jail.local with proper structure")
	return nil
}

// updateJailLocalDefaultSection updates only the [DEFAULT] section values in jail.local
// while preserving the banner, action_mwlg, and action override
func updateJailLocalDefaultSection(settings AppSettings) error {
	content, err := os.ReadFile(jailFile)
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	var outputLines []string
	inDefault := false
	defaultUpdated := false

	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banaction := settings.Banaction
	if banaction == "" {
		banaction = "nftables-multiport"
	}
	banactionAllports := settings.BanactionAllports
	if banactionAllports == "" {
		banactionAllports = "nftables-allports"
	}
	chain := settings.Chain
	if chain == "" {
		chain = "INPUT"
	}
	// Keys to update
	keysToUpdate := map[string]string{
		"enabled":            fmt.Sprintf("enabled = %t", settings.DefaultJailEnable),
		"bantime.increment":  fmt.Sprintf("bantime.increment = %t", settings.BantimeIncrement),
		"ignoreip":           fmt.Sprintf("ignoreip = %s", ignoreIPStr),
		"bantime":            fmt.Sprintf("bantime = %s", settings.Bantime),
		"findtime":           fmt.Sprintf("findtime = %s", settings.Findtime),
		"maxretry":           fmt.Sprintf("maxretry = %d", settings.Maxretry),
		"banaction":          fmt.Sprintf("banaction = %s", banaction),
		"banaction_allports": fmt.Sprintf("banaction_allports = %s", banactionAllports),
		"chain":              fmt.Sprintf("chain = %s", chain),
	}
	if settings.BantimeRndtime != "" {
		keysToUpdate["bantime.rndtime"] = fmt.Sprintf("bantime.rndtime = %s", settings.BantimeRndtime)
	}
	defaultKeysOrder := []string{"enabled", "bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "banaction", "banaction_allports", "chain"}
	if settings.BantimeRndtime != "" {
		defaultKeysOrder = append(defaultKeysOrder, "bantime.rndtime")
	}
	keysUpdated := make(map[string]bool)

	// Always add the full banner at the start
	outputLines = append(outputLines, strings.Split(strings.TrimRight(jailLocalBanner, "\n"), "\n")...)

	// Skip everything before [DEFAULT] section (old banner, comments, empty lines)
	foundSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Found a section - stop skipping and process this line
			foundSection = true
		}
		if !foundSection {
			// Skip lines before any section (old banner, comments, empty lines)
			continue
		}

		// Process lines after we found a section
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sectionName := strings.Trim(trimmed, "[]")
			if sectionName == "DEFAULT" {
				inDefault = true
				outputLines = append(outputLines, line)
			} else {
				inDefault = false
				outputLines = append(outputLines, line)
			}
		} else if inDefault {
			// Check if this line is a key we need to update
			keyUpdated := false
			// When user cleared bantime.rndtime, remove the line from config instead of keeping old value
			if settings.BantimeRndtime == "" {
				if matched, _ := regexp.MatchString(`^\s*bantime\.rndtime\s*=`, trimmed); matched {
					keyUpdated = true
					defaultUpdated = true
					// don't append: line is removed
				}
			}
			if !keyUpdated {
				for key, newValue := range keysToUpdate {
					keyPattern := "^\\s*" + regexp.QuoteMeta(key) + "\\s*="
					if matched, _ := regexp.MatchString(keyPattern, trimmed); matched {
						outputLines = append(outputLines, newValue)
						keysUpdated[key] = true
						keyUpdated = true
						defaultUpdated = true
						break
					}
				}
			}
			if !keyUpdated {
				// Keep the line as-is
				outputLines = append(outputLines, line)
			}
		} else {
			// Keep lines outside DEFAULT section
			outputLines = append(outputLines, line)
		}
	}

	// Add any missing keys to the DEFAULT section
	if inDefault {
		for _, key := range defaultKeysOrder {
			if newValue, ok := keysToUpdate[key]; ok && !keysUpdated[key] {
				for i, outputLine := range outputLines {
					if strings.TrimSpace(outputLine) == "[DEFAULT]" {
						outputLines = append(outputLines[:i+1], append([]string{newValue}, outputLines[i+1:]...)...)
						defaultUpdated = true
						break
					}
				}
			}
		}
	}

	if defaultUpdated {
		newContent := strings.Join(outputLines, "\n")
		if err := os.WriteFile(jailFile, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail.local: %w", err)
		}
		DebugLog("Updated DEFAULT section in jail.local")
	}

	return nil
}

// writeFail2banAction creates or updates the action file with the AlertCountries.
func writeFail2banAction(callbackURL, serverID string) error {
	DebugLog("Running initial writeFail2banAction()") // entry point
	DebugLog("----------------------------")

	// Check if /etc/fail2ban/action.d directory exists (fail2ban must be installed)
	if _, err := os.Stat(filepath.Dir(actionFile)); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban is not installed: /etc/fail2ban/action.d directory does not exist. Please install fail2ban package first")
	}

	settings := GetSettings()
	actionConfig := BuildFail2banActionConfig(callbackURL, serverID, settings.CallbackSecret)
	err := os.WriteFile(actionFile, []byte(actionConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write action file: %w", err)
	}

	DebugLog("Custom-action file successfully written to %s\n", actionFile)
	return nil
}

func cloneServer(src Fail2banServer) Fail2banServer {
	dst := src
	if src.Tags != nil {
		dst.Tags = append([]string{}, src.Tags...)
	}
	dst.enabledSet = src.enabledSet
	return dst
}

func BuildFail2banActionConfig(callbackURL, serverID, secret string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	if trimmed == "" {
		trimmed = "http://127.0.0.1:8080"
	}
	if serverID == "" {
		serverID = "local"
	}
	if secret == "" {
		// If secret is empty, get it from settings (should be generated by setDefaultsLocked)
		settings := GetSettings()
		secret = settings.CallbackSecret
		// Last resort: if still empty, generate one (shouldn't happen)
		if secret == "" {
			secret = generateCallbackSecret()
		}
	}
	// Determine if we need to use -k flag for HTTPS with self-signed certificates
	// This allows curl to work with self-signed, in-house CA certificates
	// For HTTP URLs, we use a empty string.
	curlInsecureFlag := ""
	if strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		curlInsecureFlag = " -k"
	}

	config := strings.ReplaceAll(fail2banActionTemplate, actionCallbackPlaceholder, trimmed)
	config = strings.ReplaceAll(config, actionServerIDPlaceholder, serverID)
	config = strings.ReplaceAll(config, actionSecretPlaceholder, secret)
	config = strings.ReplaceAll(config, actionCurlInsecureFlag, curlInsecureFlag)
	return config
}

// generateCallbackSecret generates a 42-character random secret using crypto/rand.
func generateCallbackSecret() string {
	// Generate 32 random bytes (256 bits of entropy)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to hex encoding if crypto/rand fails (shouldn't happen)
		fallbackBytes := make([]byte, 21) // 21 bytes = 42 hex chars
		if _, err := rand.Read(fallbackBytes); err != nil {
			// Last resort: use time-based seed (not ideal but better than nothing)
			return fmt.Sprintf("%042x", time.Now().UnixNano())
		}
		return hex.EncodeToString(fallbackBytes)
	}
	// Use base64 URL-safe encoding, which gives us 43 chars for 32 bytes
	// We need exactly 42, so we'll truncate the last character (which is padding anyway)
	encoded := base64.URLEncoding.EncodeToString(bytes)
	// Base64 URL encoding of 32 bytes = 43 chars, take first 42
	if len(encoded) >= 42 {
		return encoded[:42]
	}
	// If somehow shorter, pad with random hex
	return encoded + hex.EncodeToString(bytes)[:42-len(encoded)]
}

func getCallbackURLLocked() string {
	url := strings.TrimSpace(currentSettings.CallbackURL)
	if url == "" {
		port := currentSettings.Port
		if port == 0 {
			port = 8080
		}
		url = fmt.Sprintf("http://127.0.0.1:%d", port)
	}
	return strings.TrimRight(url, "/")
}

// GetCallbackURL returns the callback URL used by Fail2ban agents.
func GetCallbackURL() string {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return getCallbackURLLocked()
}

// EnsureLocalFail2banAction ensures the local Fail2ban action files exist when the local connector is enabled.
func EnsureLocalFail2banAction(server Fail2banServer) error {
	if !server.Enabled {
		return nil
	}
	settingsLock.RLock()
	callbackURL := getCallbackURLLocked()
	settingsLock.RUnlock()
	return ensureFail2banActionFiles(callbackURL, server.ID)
}

func serverByIDLocked(id string) (Fail2banServer, bool) {
	for _, srv := range currentSettings.Servers {
		if srv.ID == id {
			return cloneServer(srv), true
		}
	}
	return Fail2banServer{}, false
}

// ListServers returns a copy of the configured Fail2ban servers.
func ListServers() []Fail2banServer {
	settingsLock.RLock()
	defer settingsLock.RUnlock()

	out := make([]Fail2banServer, len(currentSettings.Servers))
	for idx, srv := range currentSettings.Servers {
		out[idx] = cloneServer(srv)
	}
	return out
}

// GetServerByID returns the server matching the supplied ID.
func GetServerByID(id string) (Fail2banServer, bool) {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	srv, ok := serverByIDLocked(id)
	if !ok {
		return Fail2banServer{}, false
	}
	return cloneServer(srv), true
}

// GetServerByHostname returns the first server matching the hostname.
func GetServerByHostname(hostname string) (Fail2banServer, bool) {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	for _, srv := range currentSettings.Servers {
		if strings.EqualFold(srv.Hostname, hostname) {
			return cloneServer(srv), true
		}
	}
	return Fail2banServer{}, false
}

// GetDefaultServer returns the default server.
func GetDefaultServer() Fail2banServer {
	settingsLock.RLock()
	defer settingsLock.RUnlock()

	for _, srv := range currentSettings.Servers {
		if srv.IsDefault && srv.Enabled {
			return cloneServer(srv)
		}
	}
	for _, srv := range currentSettings.Servers {
		if srv.Enabled {
			return cloneServer(srv)
		}
	}
	return Fail2banServer{}
}

// UpsertServer adds or updates a Fail2ban server and persists the settings.
func UpsertServer(input Fail2banServer) (Fail2banServer, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	now := time.Now().UTC()
	input.Type = strings.ToLower(strings.TrimSpace(input.Type))
	if input.ID == "" {
		input.ID = generateServerID()
		input.CreatedAt = now
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = now
	}
	input.UpdatedAt = now

	if input.Type == "" {
		input.Type = "local"
	}
	if !input.enabledSet {
		if input.Type == "local" {
			input.Enabled = false
		} else {
			input.Enabled = true
		}
		input.enabledSet = true
	}
	if input.Type == "local" && input.SocketPath == "" {
		input.SocketPath = "/var/run/fail2ban/fail2ban.sock"
	}
	if input.Type == "local" && input.LogPath == "" {
		input.LogPath = "/var/log/fail2ban.log"
	}
	if input.Name == "" {
		input.Name = "Fail2ban Server " + input.ID
	}
	replaced := false
	for idx, srv := range currentSettings.Servers {
		if srv.ID == input.ID {
			if !input.enabledSet {
				input.Enabled = srv.Enabled
				input.enabledSet = true
			}
			if !input.Enabled {
				input.IsDefault = false
			}
			if input.IsDefault {
				clearDefaultLocked()
			}
			// preserve created timestamp if incoming zero
			if input.CreatedAt.IsZero() {
				input.CreatedAt = srv.CreatedAt
			}
			currentSettings.Servers[idx] = input
			replaced = true
			break
		}
	}

	if !replaced {
		if input.IsDefault {
			clearDefaultLocked()
		}
		if len(currentSettings.Servers) == 0 && input.Enabled {
			input.IsDefault = true
		}
		currentSettings.Servers = append(currentSettings.Servers, input)
	}

	normalizeServersLocked()
	if err := persistServersLocked(); err != nil {
		return Fail2banServer{}, err
	}
	srv, _ := serverByIDLocked(input.ID)
	return cloneServer(srv), nil
}

func clearDefaultLocked() {
	for idx := range currentSettings.Servers {
		currentSettings.Servers[idx].IsDefault = false
	}
}

func setServerRestartFlagLocked(serverID string, value bool) bool {
	for idx := range currentSettings.Servers {
		if currentSettings.Servers[idx].ID == serverID {
			currentSettings.Servers[idx].RestartNeeded = value
			return true
		}
	}
	return false
}

func anyServerNeedsRestartLocked() bool {
	for _, srv := range currentSettings.Servers {
		if srv.RestartNeeded {
			return true
		}
	}
	return false
}

func updateGlobalRestartFlagLocked() {
	currentSettings.RestartNeeded = anyServerNeedsRestartLocked()
}

func markAllServersRestartLocked() {
	for idx := range currentSettings.Servers {
		currentSettings.Servers[idx].RestartNeeded = true
	}
}

// DeleteServer removes a server by ID.
func DeleteServer(id string) error {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	if len(currentSettings.Servers) == 0 {
		return fmt.Errorf("no servers configured")
	}

	index := -1
	for i, srv := range currentSettings.Servers {
		if srv.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		return fmt.Errorf("server %s not found", id)
	}

	currentSettings.Servers = append(currentSettings.Servers[:index], currentSettings.Servers[index+1:]...)
	normalizeServersLocked()
	return persistServersLocked()
}

// SetDefaultServer marks the specified server as default.
func SetDefaultServer(id string) (Fail2banServer, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	found := false
	for idx := range currentSettings.Servers {
		srv := &currentSettings.Servers[idx]
		if srv.ID == id {
			found = true
			srv.IsDefault = true
			if !srv.Enabled {
				srv.Enabled = true
				srv.enabledSet = true
			}
			srv.UpdatedAt = time.Now().UTC()
		} else {
			srv.IsDefault = false
		}
	}
	if !found {
		return Fail2banServer{}, fmt.Errorf("server %s not found", id)
	}

	normalizeServersLocked()
	if err := persistServersLocked(); err != nil {
		return Fail2banServer{}, err
	}
	srv, _ := serverByIDLocked(id)
	return cloneServer(srv), nil
}

// GetSettings returns a copy of the current settings
// GetPortFromEnv returns the PORT environment variable value if set, and whether it's set
func GetPortFromEnv() (int, bool) {
	portEnv := os.Getenv("PORT")
	if portEnv == "" {
		return 0, false
	}
	if port, err := strconv.Atoi(portEnv); err == nil && port > 0 && port <= 65535 {
		return port, true
	}
	return 0, false
}

// GetBindAddressFromEnv returns the BIND_ADDRESS environment variable value if set, and whether it's set
// If not set, returns "0.0.0.0" as the default bind address
// Validates that the address is a valid IP address format
func GetBindAddressFromEnv() (string, bool) {
	bindAddrEnv := os.Getenv("BIND_ADDRESS")
	if bindAddrEnv == "" {
		return "0.0.0.0", false
	}
	// Validate that it's a valid IP address format using net.ParseIP
	if ip := net.ParseIP(bindAddrEnv); ip != nil {
		return bindAddrEnv, true
	}
	// Invalid format, return default
	return "0.0.0.0", false
}

// GetOIDCConfigFromEnv reads OIDC configuration from environment variables
// Returns nil if OIDC is not enabled
func GetOIDCConfigFromEnv() (*OIDCConfig, error) {
	enabled := os.Getenv("OIDC_ENABLED")
	if enabled != "true" && enabled != "1" {
		return nil, nil // OIDC not enabled
	}

	config := &OIDCConfig{
		Enabled: true,
	}

	// Required fields
	config.Provider = os.Getenv("OIDC_PROVIDER")
	if config.Provider == "" {
		return nil, fmt.Errorf("OIDC_PROVIDER environment variable is required when OIDC_ENABLED=true")
	}
	if config.Provider != "keycloak" && config.Provider != "authentik" && config.Provider != "pocketid" {
		return nil, fmt.Errorf("OIDC_PROVIDER must be one of: keycloak, authentik, pocketid")
	}

	config.IssuerURL = os.Getenv("OIDC_ISSUER_URL")
	if config.IssuerURL == "" {
		return nil, fmt.Errorf("OIDC_ISSUER_URL environment variable is required when OIDC_ENABLED=true")
	}

	config.ClientID = os.Getenv("OIDC_CLIENT_ID")
	if config.ClientID == "" {
		return nil, fmt.Errorf("OIDC_CLIENT_ID environment variable is required when OIDC_ENABLED=true")
	}

	config.ClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	// If client secret is "auto-configured", try to read from file
	// This is primarily used for Keycloak's automatic client setup in development
	if config.ClientSecret == "auto-configured" {
		secretFile := os.Getenv("OIDC_CLIENT_SECRET_FILE")
		if secretFile == "" {
			secretFile = "/config/keycloak-client-secret" // Default path for Keycloak auto-configuration
		}
		if secretBytes, err := os.ReadFile(secretFile); err == nil {
			config.ClientSecret = strings.TrimSpace(string(secretBytes))
		} else {
			return nil, fmt.Errorf("OIDC_CLIENT_SECRET is set to 'auto-configured' but could not read from file %s: %w", secretFile, err)
		}
	}
	if config.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC_CLIENT_SECRET environment variable is required when OIDC_ENABLED=true")
	}

	config.RedirectURL = os.Getenv("OIDC_REDIRECT_URL")
	if config.RedirectURL == "" {
		return nil, fmt.Errorf("OIDC_REDIRECT_URL environment variable is required when OIDC_ENABLED=true")
	}

	// Optional fields with defaults
	scopesEnv := os.Getenv("OIDC_SCOPES")
	if scopesEnv != "" {
		config.Scopes = strings.Split(scopesEnv, ",")
		for i := range config.Scopes {
			config.Scopes[i] = strings.TrimSpace(config.Scopes[i])
		}
	} else {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	// Set default session max age
	config.SessionMaxAge = 3600 // Default: 1 hour
	sessionMaxAgeEnv := os.Getenv("OIDC_SESSION_MAX_AGE")
	if sessionMaxAgeEnv != "" {
		if maxAge, err := strconv.Atoi(sessionMaxAgeEnv); err == nil && maxAge > 0 {
			config.SessionMaxAge = maxAge
		}
	}

	// Skip login page option (default: false)
	skipLoginPageEnv := os.Getenv("OIDC_SKIP_LOGINPAGE")
	config.SkipLoginPage = skipLoginPageEnv == "true" || skipLoginPageEnv == "1"

	config.SessionSecret = os.Getenv("OIDC_SESSION_SECRET")
	if config.SessionSecret == "" {
		// Generate a random session secret
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			return nil, fmt.Errorf("failed to generate session secret: %w", err)
		}
		config.SessionSecret = base64.URLEncoding.EncodeToString(secretBytes)
	}

	skipVerifyEnv := os.Getenv("OIDC_SKIP_VERIFY")
	config.SkipVerify = (skipVerifyEnv == "true" || skipVerifyEnv == "1")

	config.UsernameClaim = os.Getenv("OIDC_USERNAME_CLAIM")
	if config.UsernameClaim == "" {
		config.UsernameClaim = "preferred_username" // Default claim
	}

	config.LogoutURL = os.Getenv("OIDC_LOGOUT_URL") // Optional

	return config, nil
}

func GetSettings() AppSettings {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return currentSettings
}

// MarkRestartNeeded marks the specified server as requiring a restart.
func MarkRestartNeeded(serverID string) error {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	if serverID == "" {
		return fmt.Errorf("server id must be provided")
	}

	if !setServerRestartFlagLocked(serverID, true) {
		return fmt.Errorf("server %s not found", serverID)
	}

	updateGlobalRestartFlagLocked()
	if err := persistServersLocked(); err != nil {
		return err
	}
	return persistAppSettingsLocked()
}

// MarkRestartDone marks the specified server as no longer requiring a restart.
func MarkRestartDone(serverID string) error {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	if serverID == "" {
		return fmt.Errorf("server id must be provided")
	}

	if !setServerRestartFlagLocked(serverID, false) {
		return fmt.Errorf("server %s not found", serverID)
	}

	updateGlobalRestartFlagLocked()
	if err := persistServersLocked(); err != nil {
		return err
	}
	return persistAppSettingsLocked()
}

// UpdateSettings merges new settings with old and sets restartNeeded if needed
func UpdateSettings(new AppSettings) (AppSettings, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	DebugLog("--- Locked settings for update ---") // Log lock acquisition

	old := currentSettings

	// If certain fields change, we mark reload needed
	// Compare IgnoreIPs arrays
	ignoreIPsChanged := false
	if len(old.IgnoreIPs) != len(new.IgnoreIPs) {
		ignoreIPsChanged = true
	} else {
		for i := range old.IgnoreIPs {
			if old.IgnoreIPs[i] != new.IgnoreIPs[i] {
				ignoreIPsChanged = true
				break
			}
		}
	}
	restartTriggered := old.BantimeIncrement != new.BantimeIncrement ||
		old.DefaultJailEnable != new.DefaultJailEnable ||
		ignoreIPsChanged ||
		old.Bantime != new.Bantime ||
		old.Findtime != new.Findtime ||
		old.Maxretry != new.Maxretry
	if restartTriggered {
		new.RestartNeeded = true
	} else {
		new.RestartNeeded = anyServerNeedsRestartLocked()
	}

	new.CallbackURL = strings.TrimSpace(new.CallbackURL)

	// Auto-update callback URL if port changed and callback URL is still using default localhost pattern
	oldPort := currentSettings.Port
	if new.Port != oldPort && new.Port > 0 {
		// Check if callback URL matches the default localhost pattern
		oldPattern := regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)
		if oldPattern.MatchString(new.CallbackURL) || new.CallbackURL == "" {
			// Update to match new port
			new.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d", new.Port)
		}
	}

	if len(new.Servers) == 0 && len(currentSettings.Servers) > 0 {
		new.Servers = make([]Fail2banServer, len(currentSettings.Servers))
		for i, srv := range currentSettings.Servers {
			new.Servers[i] = cloneServer(srv)
		}
	}
	currentSettings = new
	setDefaultsLocked()
	if currentSettings.RestartNeeded && restartTriggered {
		markAllServersRestartLocked()
		updateGlobalRestartFlagLocked()
	}
	DebugLog("New settings applied: %v", currentSettings) // Log settings applied

	// Update console log enabled state if it changed
	if old.ConsoleOutput != new.ConsoleOutput {
		// Import web package to update console log state
		// We'll handle this via a callback or direct call
		updateConsoleLogState(new.ConsoleOutput)
	}

	if err := persistAllLocked(); err != nil {
		fmt.Println("Error saving settings:", err)
		return currentSettings, err
	}
	return currentSettings, nil
}

// updateConsoleLogState updates the console log writer enabled state
// This is called from UpdateSettings when console output setting changes
var updateConsoleLogStateFunc func(bool)

// SetUpdateConsoleLogStateFunc sets the callback function to update console log state
func SetUpdateConsoleLogStateFunc(fn func(bool)) {
	updateConsoleLogStateFunc = fn
}

func updateConsoleLogState(enabled bool) {
	if updateConsoleLogStateFunc != nil {
		updateConsoleLogStateFunc(enabled)
	}
}
