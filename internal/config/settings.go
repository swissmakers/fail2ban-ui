// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
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

// =========================================================================
//  Types
// =========================================================================

type AppSettings struct {
	Language             string                `json:"language"`
	Port                 int                   `json:"port"`
	Debug                bool                  `json:"debug"`
	RestartNeeded        bool                  `json:"restartNeeded"`
	AlertCountries       []string              `json:"alertCountries"`
	SMTP                 SMTPSettings          `json:"smtp"`
	CallbackURL          string                `json:"callbackUrl"`
	CallbackSecret       string                `json:"callbackSecret"`
	AdvancedActions      AdvancedActionsConfig `json:"advancedActions"`
	Servers              []Fail2banServer      `json:"servers"`
	BantimeIncrement     bool                  `json:"bantimeIncrement"`
	DefaultJailEnable    bool                  `json:"defaultJailEnable"`
	IgnoreIPs            []string              `json:"ignoreips"`
	Bantime              string                `json:"bantime"`
	Findtime             string                `json:"findtime"`
	Maxretry             int                   `json:"maxretry"`
	Destemail            string                `json:"destemail"`
	Banaction            string                `json:"banaction"`
	BanactionAllports    string                `json:"banactionAllports"`
	Chain                string                `json:"chain"`
	BantimeRndtime       string                `json:"bantimeRndtime"`
	GeoIPProvider        string                `json:"geoipProvider"`
	GeoIPDatabasePath    string                `json:"geoipDatabasePath"`
	MaxLogLines          int                   `json:"maxLogLines"`
	EmailAlertsForBans   bool                  `json:"emailAlertsForBans"`
	EmailAlertsForUnbans bool                  `json:"emailAlertsForUnbans"`
	AlertProvider        string                `json:"alertProvider"`
	Webhook              WebhookSettings       `json:"webhook"`
	Elasticsearch        ElasticsearchSettings `json:"elasticsearch"`
	ConsoleOutput        bool                  `json:"consoleOutput"`
}

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

type Fail2banServer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Host          string    `json:"host,omitempty"`
	Port          int       `json:"port,omitempty"`
	SocketPath    string    `json:"socketPath,omitempty"`
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
	enabledSet    bool
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

type WebhookSettings struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	Headers       map[string]string `json:"headers"`
	SkipTLSVerify bool              `json:"skipTLSVerify"`
}

type ElasticsearchSettings struct {
	URL           string `json:"url"`
	Index         string `json:"index"`
	APIKey        string `json:"apiKey"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

type OIDCConfig struct {
	Enabled       bool     `json:"enabled"`
	Provider      string   `json:"provider"`
	IssuerURL     string   `json:"issuerURL"`
	ClientID      string   `json:"clientID"`
	ClientSecret  string   `json:"clientSecret"`
	RedirectURL   string   `json:"redirectURL"`
	Scopes        []string `json:"scopes"`
	SessionSecret string   `json:"sessionSecret"`
	SessionMaxAge int      `json:"sessionMaxAge"`
	SkipVerify    bool     `json:"skipVerify"`
	UsernameClaim string   `json:"usernameClaim"`
	LogoutURL     string   `json:"logoutURL"`
	SkipLoginPage bool     `json:"skipLoginPage"`
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

// =========================================================================
//  Constants
// =========================================================================

const (
	settingsFile              = "fail2ban-ui-settings.json"
	jailFile                  = "/etc/fail2ban/jail.local"
	actionFile                = "/etc/fail2ban/action.d/ui-custom-action.conf"
	actionCallbackPlaceholder = "__CALLBACK_URL__"
	actionServerIDPlaceholder = "__SERVER_ID__"
	actionSecretPlaceholder   = "__CALLBACK_SECRET__"
	actionCurlInsecureFlag    = "__CURL_INSECURE_FLAG__"
)

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
const fail2banActionTemplate = `[Definition]

# Bypasses ban/unban for restored bans
norestored = 1

# Executes a cURL request to notify our API when an IP is banned.
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

# Executes a cURL request to notify our API when an IP is unbanned.
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

// =========================================================================
//  Package Variables
// =========================================================================

var (
	currentSettings     AppSettings
	settingsLock        sync.RWMutex
	errSettingsNotFound = errors.New("settings not found")
	backgroundCtx       = context.Background()
)

// Customizes JSON unmarshaling to distinguish between explicit false and unset values.
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

// =========================================================================
//  Initialization
// =========================================================================

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

// =========================================================================
//  Persistence
// =========================================================================

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
	if rec.AlertProvider != "" {
		currentSettings.AlertProvider = rec.AlertProvider
	} else {
		currentSettings.AlertProvider = "email"
	}
	if rec.WebhookJSON != "" {
		var wh WebhookSettings
		if err := json.Unmarshal([]byte(rec.WebhookJSON), &wh); err == nil {
			currentSettings.Webhook = wh
		}
	}
	if rec.ElasticsearchJSON != "" {
		var es ElasticsearchSettings
		if err := json.Unmarshal([]byte(rec.ElasticsearchJSON), &es); err == nil {
			currentSettings.Elasticsearch = es
		}
	}
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

	webhookBytes, err := json.Marshal(currentSettings.Webhook)
	if err != nil {
		return storage.AppSettingsRecord{}, err
	}

	esBytes, err := json.Marshal(currentSettings.Elasticsearch)
	if err != nil {
		return storage.AppSettingsRecord{}, err
	}

	alertProvider := currentSettings.AlertProvider
	if alertProvider == "" {
		alertProvider = "email"
	}

	return storage.AppSettingsRecord{
		Language:               currentSettings.Language,
		Port:                   currentSettings.Port,
		Debug:                  currentSettings.Debug,
		RestartNeeded:          currentSettings.RestartNeeded,
		CallbackURL:            currentSettings.CallbackURL,
		CallbackSecret:         currentSettings.CallbackSecret,
		AlertCountriesJSON:     string(countryBytes),
		EmailAlertsForBans:     currentSettings.EmailAlertsForBans,
		EmailAlertsForUnbans:   currentSettings.EmailAlertsForUnbans,
		SMTPHost:               currentSettings.SMTP.Host,
		SMTPPort:               currentSettings.SMTP.Port,
		SMTPUsername:           currentSettings.SMTP.Username,
		SMTPPassword:           currentSettings.SMTP.Password,
		SMTPFrom:               currentSettings.SMTP.From,
		SMTPUseTLS:             currentSettings.SMTP.UseTLS,
		SMTPInsecureSkipVerify: currentSettings.SMTP.InsecureSkipVerify,
		SMTPAuthMethod:         currentSettings.SMTP.AuthMethod,
		BantimeIncrement:       currentSettings.BantimeIncrement,
		DefaultJailEnable:      currentSettings.DefaultJailEnable,
		IgnoreIP:               strings.Join(currentSettings.IgnoreIPs, " "),
		Bantime:                currentSettings.Bantime,
		Findtime:               currentSettings.Findtime,
		MaxRetry:               currentSettings.Maxretry,
		DestEmail:              currentSettings.Destemail,
		Banaction:              currentSettings.Banaction,
		BanactionAllports:      currentSettings.BanactionAllports,
		Chain:                  currentSettings.Chain,
		BantimeRndtime:         currentSettings.BantimeRndtime,
		AdvancedActionsJSON:    string(advancedBytes),
		GeoIPProvider:          currentSettings.GeoIPProvider,
		GeoIPDatabasePath:      currentSettings.GeoIPDatabasePath,
		MaxLogLines:            currentSettings.MaxLogLines,
		AlertProvider:          alertProvider,
		WebhookJSON:            string(webhookBytes),
		ElasticsearchJSON:      string(esBytes),
		ConsoleOutput:          currentSettings.ConsoleOutput,
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

func setDefaults() {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	setDefaultsLocked()
}

func setDefaultsLocked() {
	if currentSettings.Language == "" {
		currentSettings.Language = "en"
	}
	// Set email alert defaults only when uninitialized.
	if !currentSettings.EmailAlertsForBans && !currentSettings.EmailAlertsForUnbans {
		if currentSettings.CallbackSecret == "" && currentSettings.Port == 0 {
			currentSettings.EmailAlertsForBans = true
			currentSettings.EmailAlertsForUnbans = false
		}
	}
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if port, err := strconv.Atoi(portEnv); err == nil && port > 0 && port <= 65535 {
			currentSettings.Port = port
		} else if currentSettings.Port == 0 {
			currentSettings.Port = 8080
		}
	} else if currentSettings.Port == 0 {
		currentSettings.Port = 8080
	}
	if cbURL := os.Getenv("CALLBACK_URL"); cbURL != "" {
		currentSettings.CallbackURL = strings.TrimRight(strings.TrimSpace(cbURL), "/")
	} else if currentSettings.CallbackURL == "" {
		currentSettings.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d", currentSettings.Port)
	} else {
		oldPattern := regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)
		if oldPattern.MatchString(currentSettings.CallbackURL) {
			currentSettings.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d", currentSettings.Port)
		}
	}
	if cbSecret := os.Getenv("CALLBACK_SECRET"); cbSecret != "" {
		currentSettings.CallbackSecret = strings.TrimSpace(cbSecret)
	} else if currentSettings.CallbackSecret == "" {
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

// Reads the jail.local file and merges its [DEFAULT] section values into currentSettings. (experimental)
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

// =========================================================================
//  Fail2ban File Management --> TODO: create a new connector_global.go for functions that are used by all connectors
// =========================================================================

// Ensures the local action files exist. (local connector only) -> will be moved to the connector_local.go
func ensureFail2banActionFiles(callbackURL, serverID string) error {
	DebugLog("----------------------------")
	DebugLog("ensureFail2banActionFiles called (settings.go)")
	if _, err := os.Stat(filepath.Dir(jailFile)); os.IsNotExist(err) {
		return nil
	}
	if err := EnsureJailLocalStructure(); err != nil {
		return err
	}
	return writeFail2banAction(callbackURL, serverID)
}

// Builds the content of our fail2ban-UI managed jail.local file. (used by all connectors)
func BuildJailLocalContent() string {
	settings := GetSettings()
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
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
`, settings.DefaultJailEnable, settings.BantimeIncrement, ignoreIPStr,
		settings.Bantime, settings.Findtime, settings.Maxretry,
		banaction, banactionAllports, chain)
	if settings.BantimeRndtime != "" {
		defaultSection += fmt.Sprintf("bantime.rndtime = %s\n", settings.BantimeRndtime)
	}
	defaultSection += "\n"

	actionMwlgConfig := `# Custom Fail2Ban action for UI callbacks
action_mwlg = %(action_)s
             ui-custom-action[logpath="%(logpath)s", chain="%(chain)s"]

`
	actionOverride := `# Custom Fail2Ban action applied by fail2ban-ui
action = %(action_mwlg)s
`

	return jailLocalBanner + defaultSection + actionMwlgConfig + actionOverride
}

// Ensures that the managed jail.local file is valid and exists. (used by all connectors)
func EnsureJailLocalStructure() error {
	DebugLog("Running EnsureJailLocalStructure()")
	if _, err := os.Stat(filepath.Dir(jailFile)); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban is not installed: /etc/fail2ban directory does not exist. Please install fail2ban package first")
	}
	var existingContent string
	fileExists := false
	if content, err := os.ReadFile(jailFile); err == nil {
		existingContent = string(content)
		fileExists = len(strings.TrimSpace(existingContent)) > 0
	}
	if fileExists && !strings.Contains(existingContent, "ui-custom-action") {
		DebugLog("jail.local file exists but is not managed by Fail2ban-UI - skipping overwrite")
		return nil
	}
	if err := os.WriteFile(jailFile, []byte(BuildJailLocalContent()), 0644); err != nil {
		return fmt.Errorf("failed to write jail.local: %v", err)
	}
	DebugLog("Created/updated jail.local with proper content.")
	return nil
}

// Writes the custom-action file. (for local connector only) -> will be moved to the connector_local.go
func writeFail2banAction(callbackURL, serverID string) error {
	DebugLog("Running initial writeFail2banAction()")
	DebugLog("----------------------------")
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

// Builds the content of our fail2ban-UI custom-action file. (used by all connectors)
func BuildFail2banActionConfig(callbackURL, serverID, secret string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	if trimmed == "" {
		trimmed = "http://127.0.0.1:8080"
	}
	if serverID == "" {
		serverID = "local"
	}
	if secret == "" {
		settings := GetSettings()
		secret = settings.CallbackSecret
		if secret == "" {
			secret = generateCallbackSecret()
		}
	}
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

// Generates a 42-character random secret for the callback secret.
func generateCallbackSecret() string {
	// Generate first 32 random bytes (256 bits of entropy)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		fallbackBytes := make([]byte, 21)
		if _, err := rand.Read(fallbackBytes); err != nil {
			return fmt.Sprintf("%042x", time.Now().UnixNano())
		}
		return hex.EncodeToString(fallbackBytes)
	}
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) >= 42 {
		return encoded[:42]
	}
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

func GetCallbackURL() string {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return getCallbackURLLocked()
}

// Ensures the local Fail2ban action but only when the server is enabled. (local connector only)
func EnsureLocalFail2banAction(server Fail2banServer) error {
	if !server.Enabled {
		return nil
	}
	settingsLock.RLock()
	callbackURL := getCallbackURLLocked()
	settingsLock.RUnlock()
	return ensureFail2banActionFiles(callbackURL, server.ID)
}

// =========================================================================
//  Server Management
// =========================================================================

func serverByIDLocked(id string) (Fail2banServer, bool) {
	for _, srv := range currentSettings.Servers {
		if srv.ID == id {
			return cloneServer(srv), true
		}
	}
	return Fail2banServer{}, false
}

func ListServers() []Fail2banServer {
	settingsLock.RLock()
	defer settingsLock.RUnlock()

	out := make([]Fail2banServer, len(currentSettings.Servers))
	for idx, srv := range currentSettings.Servers {
		out[idx] = cloneServer(srv)
	}
	return out
}

func GetServerByID(id string) (Fail2banServer, bool) {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	srv, ok := serverByIDLocked(id)
	if !ok {
		return Fail2banServer{}, false
	}
	return cloneServer(srv), true
}

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

// Adds or updates a Fail2ban server.
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

/*func setServerRestartFlagLocked(serverID string, value bool) bool {
	for idx := range currentSettings.Servers {
		if currentSettings.Servers[idx].ID == serverID {
			currentSettings.Servers[idx].RestartNeeded = value
			return true
		}
	}
	return false
}*/

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

// Deletes a server by ID.
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

// Marks the specified server as default.
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

// =========================================================================
//  Get Settings from Environment Variables
// =========================================================================

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

func GetCallbackURLFromEnv() (string, bool) {
	v := strings.TrimSpace(os.Getenv("CALLBACK_URL"))
	if v == "" {
		return "", false
	}
	return strings.TrimRight(v, "/"), true
}

func GetBindAddressFromEnv() (string, bool) {
	bindAddrEnv := os.Getenv("BIND_ADDRESS")
	if bindAddrEnv == "" {
		return "0.0.0.0", false
	}
	if ip := net.ParseIP(bindAddrEnv); ip != nil {
		return bindAddrEnv, true
	}
	return "0.0.0.0", false
}

// =========================================================================
//  OIDC Configuration from Env
// =========================================================================

// Returns the OIDC configuration from environment. Returns nil if OIDC is not enabled.
func GetOIDCConfigFromEnv() (*OIDCConfig, error) {
	enabled := os.Getenv("OIDC_ENABLED")
	if enabled != "true" && enabled != "1" {
		return nil, nil
	}
	config := &OIDCConfig{
		Enabled: true,
	}
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
	if config.ClientSecret == "auto-configured" {
		secretFile := os.Getenv("OIDC_CLIENT_SECRET_FILE")
		if secretFile == "" {
			secretFile = "/config/keycloak-client-secret"
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
	scopesEnv := os.Getenv("OIDC_SCOPES")

	if scopesEnv != "" {
		config.Scopes = strings.Split(scopesEnv, ",")
		for i := range config.Scopes {
			config.Scopes[i] = strings.TrimSpace(config.Scopes[i])
		}
	} else {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	config.SessionMaxAge = 3600
	sessionMaxAgeEnv := os.Getenv("OIDC_SESSION_MAX_AGE")

	if sessionMaxAgeEnv != "" {
		if maxAge, err := strconv.Atoi(sessionMaxAgeEnv); err == nil && maxAge > 0 {
			config.SessionMaxAge = maxAge
		}
	}

	skipLoginPageEnv := os.Getenv("OIDC_SKIP_LOGINPAGE")
	config.SkipLoginPage = skipLoginPageEnv == "true" || skipLoginPageEnv == "1"
	config.SessionSecret = os.Getenv("OIDC_SESSION_SECRET")

	if config.SessionSecret == "" {
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
		config.UsernameClaim = "preferred_username"
	}
	config.LogoutURL = os.Getenv("OIDC_LOGOUT_URL")
	return config, nil
}

// Returns a copy of the current app settings.
func GetSettings() AppSettings {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return currentSettings
}

// =========================================================================
//  Restart Tracking
// =========================================================================

// Marks the specified server as requiring a restart. -- currently not used
/*func MarkRestartNeeded(serverID string) error {
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

// Marks the specified server as no longer requiring a restart.
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
*/

func UpdateSettings(new AppSettings) (AppSettings, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	DebugLog("--- Locked settings for update ---")
	old := currentSettings
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
	oldPort := currentSettings.Port
	if new.Port != oldPort && new.Port > 0 {
		oldPattern := regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)
		if oldPattern.MatchString(new.CallbackURL) || new.CallbackURL == "" {
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
	DebugLog("New settings applied: %v", currentSettings)
	if old.ConsoleOutput != new.ConsoleOutput {
		updateConsoleLogState(new.ConsoleOutput)
	}
	if err := persistAllLocked(); err != nil {
		fmt.Println("Error saving settings:", err)
		return currentSettings, err
	}
	return currentSettings, nil
}

// Checks if "LOTR" is among the configured alert countries.
func IsLOTRModeActive(alertCountries []string) bool {
	for _, country := range alertCountries {
		if strings.EqualFold(country, "LOTR") {
			return true
		}
	}
	return false
}

// =========================================================================
//  Console Log State
// =========================================================================

var updateConsoleLogStateFunc func(bool)

// Sets the callback to update console log enabled state.
func SetUpdateConsoleLogStateFunc(fn func(bool)) {
	updateConsoleLogStateFunc = fn
}

func updateConsoleLogState(enabled bool) {
	if updateConsoleLogStateFunc != nil {
		updateConsoleLogStateFunc(enabled)
	}
}
