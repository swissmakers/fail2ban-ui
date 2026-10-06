// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
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
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Types
// =========================================================================

type Fail2banServer = shared.Fail2banServer

type AppSettings struct {
	Language             string                `json:"language"`
	Port                 int                   `json:"port"`
	Debug                bool                  `json:"debug"`
	AlertCountries       []string              `json:"alertCountries"`
	SMTP                 SMTPSettings          `json:"smtp"`
	CallbackURL          string                `json:"callbackUrl"`
	CallbackSecret       string                `json:"callbackSecret"`
	AdvancedActions      AdvancedActionsConfig `json:"advancedActions"`
	Servers              []Fail2banServer      `json:"servers,omitempty"`
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
	BantimeMaxtime       string                `json:"bantimeMaxtime"`
	BantimeFactor        string                `json:"bantimeFactor"`
	BantimeOveralljails  bool                  `json:"bantimeOveralljails"`
	GeoIPProvider        string                `json:"geoipProvider"`
	GeoIPDatabasePath    string                `json:"geoipDatabasePath"`
	MaxLogLines          int                   `json:"maxLogLines"`
	EventRetentionDays   int                   `json:"eventRetentionDays"`
	EmailAlertsForBans   bool                  `json:"emailAlertsForBans"`
	EmailAlertsForUnbans bool                  `json:"emailAlertsForUnbans"`
	AlertProvider        string                `json:"alertProvider"`
	Webhook              WebhookSettings       `json:"webhook"`
	Elasticsearch        ElasticsearchSettings `json:"elasticsearch"`
	ThreatIntel          ThreatIntelSettings   `json:"threatIntel"`
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

type AdvancedActionsConfig struct {
	Enabled     bool                        `json:"enabled"`
	Threshold   int                         `json:"threshold"`
	Integration string                      `json:"integration"`
	Mikrotik    MikrotikIntegrationSettings `json:"mikrotik"`
	PfSense     PfSenseIntegrationSettings  `json:"pfSense"`
	OPNsense    OPNsenseIntegrationSettings `json:"opnsense"`
	UniFi       UniFiIntegrationSettings    `json:"unifi"`
}

type MikrotikIntegrationSettings struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	SSHKeyPath         string `json:"sshKeyPath"`
	AddressList        string `json:"addressList"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
}

type PfSenseIntegrationSettings struct {
	BaseURL       string `json:"baseUrl"`
	APIToken      string `json:"apiToken"`
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

type UniFiIntegrationSettings struct {
	BaseURL         string `json:"baseUrl"`
	APIKey          string `json:"apiKey"`
	SiteName        string `json:"siteName"`
	TrafficListName string `json:"trafficListName"`
	SkipTLSVerify   bool   `json:"skipTLSVerify"`
}

type WebhookSettings struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	Headers       map[string]string `json:"headers"`
	SkipTLSVerify bool              `json:"skipTLSVerify"`
}

// Default alert target; the built-in logs-*-* template makes it a data stream.
const DefaultElasticsearchDataStream = "logs-fail2ban_ui.events-default"

// Maps an empty or pre-data-stream default index to the default data stream.
func ElasticsearchDataStream(index string) string {
	index = strings.TrimSpace(index)
	if index == "" || index == "fail2ban-events" {
		return DefaultElasticsearchDataStream
	}
	return index
}

type ElasticsearchSettings struct {
	URL           string `json:"url"`
	Index         string `json:"index"`
	APIKey        string `json:"apiKey"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

type ThreatIntelSettings struct {
	Provider         string `json:"provider"`
	AlienVaultAPIKey string `json:"alienVaultApiKey"`
	AbuseIPDBAPIKey  string `json:"abuseIpDbApiKey"`
}

type OIDCConfig struct {
	Enabled              bool     `json:"enabled"`
	Provider             string   `json:"provider"`
	IssuerURL            string   `json:"issuerURL"`
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	RedirectURL          string   `json:"redirectURL"`
	Scopes               []string `json:"scopes"`
	SessionSecret        string   `json:"sessionSecret"`
	SessionMaxAge        int      `json:"sessionMaxAge"`
	SkipVerify           bool     `json:"skipVerify"`
	UsernameClaim        string   `json:"usernameClaim"`
	RoleClaim            string   `json:"roleClaim"`
	AdminRoles           []string `json:"adminRoles"`
	SupportRoles         []string `json:"supportRoles"`
	AuthorizationEnabled bool     `json:"authorizationEnabled"`
	LogoutURL            string   `json:"logoutURL"`
	SkipLoginPage        bool     `json:"skipLoginPage"`
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
	defaultLocalSocketPath    = "/var/run/fail2ban/fail2ban.sock"
	actionCallbackPlaceholder = "__CALLBACK_URL__"
	actionServerIDPlaceholder = "__SERVER_ID__"
	actionSecretPlaceholder   = "__CALLBACK_SECRET__"
	actionCurlInsecureFlag    = "__CURL_INSECURE_FLAG__"
)

// The host default jail.local file used by initializeFromJailFile (experimental).
var jailFile = fail2ban.JailLocal("")

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

# Notifies the UI of a ban; detached so a slow or unreachable UI never delays the next ban.
actionban = ( event_id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; /usr/bin/curl__CURL_INSECURE_FLAG__ --fail --silent --show-error --connect-timeout 3 --max-time 8 --retry 2 --retry-delay 1 --retry-max-time 25 --retry-connrefused -X POST '__CALLBACK_URL__/api/ban' \
     -H "Content-Type: application/json" \
     -H 'X-Callback-Secret: __CALLBACK_SECRET__' \
     -H "X-Callback-Event-ID: $event_id" \
     -d "$(logpath='<logpath>'; \
           logs="$(tac $logpath 2>/dev/null | grep -a <grepopts> -wF '<ip>')"; \
           [ -z "$logs" ] && logs="$(journalctl --no-pager -r -o cat --since '-1 day' 2>/dev/null | grep -a <grepopts> -wF '<ip>')"; \
           logs="$(printf '%%s' "$logs" | LC_ALL=C tr -cd '\11\12\15\40-\176')"; \
           jq -n --arg serverId '__SERVER_ID__' \
                 --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 --arg failures '<failures>' \
                 --arg logs "$logs" \
                 '{serverId: $serverId, ip: $ip, jail: $jail, hostname: $hostname, failures: $failures, logs: $logs}')" ) </dev/null >/dev/null 2>&1 &

# Notifies the UI of an unban; detached for the same reason.
actionunban = ( event_id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; /usr/bin/curl__CURL_INSECURE_FLAG__ --fail --silent --show-error --connect-timeout 3 --max-time 8 --retry 2 --retry-delay 1 --retry-max-time 25 --retry-connrefused -X POST '__CALLBACK_URL__/api/unban' \
     -H "Content-Type: application/json" \
     -H 'X-Callback-Secret: __CALLBACK_SECRET__' \
     -H "X-Callback-Event-ID: $event_id" \
     -d "$(jq -n --arg serverId '__SERVER_ID__' \
                 --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 '{serverId: $serverId, ip: $ip, jail: $jail, hostname: $hostname}')" ) </dev/null >/dev/null 2>&1 &

actionflush = true

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

// Package-level compiled patterns
var (
	loopbackCallbackURLPattern = regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)
	jailFileKeyValuePattern    = regexp.MustCompile(`^([a-zA-Z0-9_.]+)\s*=\s*(.*)$`)
)

// =========================================================================
//  Initialization
// =========================================================================

const DefaultGeoIPDatabasePath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

func init() {
	log.SetOutput(redactingLogWriter{log.Writer()})
	registerFail2banProvider()
}

// Opens the database (empty path: ./fail2ban-ui.db) and loads the settings; call it once before reading settings.
func Init(dbPath string) error {
	if err := storage.Init(dbPath); err != nil {
		return fmt.Errorf("failed to initialise storage: %w", err)
	}
	if err := loadSettingsFromStorage(); err != nil {
		if !errors.Is(err, errSettingsNotFound) {
			log.Printf("ERROR: loading settings from storage: %v", err)
		}
		if err := migrateLegacySettings(); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("ERROR: migrating legacy settings: %v", err)
			}
			log.Printf("App settings not found, initializing from jail.local (if it exists)")
			if err := initializeFromJailFile(); err != nil {
				log.Printf("ERROR: reading jail.local: %v", err)
			}
			setDefaults()
			log.Printf("Initialized settings with defaults")
		}
	}
	if err := persistAll(); err != nil {
		log.Printf("ERROR: persisting settings: %v", err)
	}
	return nil
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
	setDebugFlag(currentSettings.Debug)
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
	refreshLogSecretsLocked()
	rec, err := toAppSettingsRecordLocked()
	if err != nil {
		return err
	}
	return storage.SaveAppSettings(backgroundCtx, rec)
}

func persistServersLocked() error {
	refreshLogSecretsLocked()
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
	setDebugFlag(rec.Debug)
	currentSettings.CallbackURL = rec.CallbackURL
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
	currentSettings.BantimeMaxtime = rec.BantimeMaxtime
	currentSettings.BantimeFactor = rec.BantimeFactor
	currentSettings.BantimeOveralljails = rec.BantimeOveralljails
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
		} else {
			DebugLog("warning: invalid alert_countries JSON in app_settings, resetting to defaults: %v", err)
			currentSettings.AlertCountries = []string{"ALL"}
		}
	}
	if rec.AdvancedActionsJSON != "" {
		var adv AdvancedActionsConfig
		if err := json.Unmarshal([]byte(rec.AdvancedActionsJSON), &adv); err == nil {
			currentSettings.AdvancedActions = adv
		} else {
			DebugLog("warning: invalid advanced_actions JSON in app_settings, resetting to defaults: %v", err)
			currentSettings.AdvancedActions = defaultAdvancedActionsConfig()
		}
	}
	currentSettings.GeoIPProvider = rec.GeoIPProvider
	currentSettings.GeoIPDatabasePath = rec.GeoIPDatabasePath
	currentSettings.MaxLogLines = rec.MaxLogLines
	currentSettings.EventRetentionDays = rec.EventRetentionDays
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
		} else {
			DebugLog("warning: invalid webhook JSON in app_settings, resetting to defaults: %v", err)
			currentSettings.Webhook = WebhookSettings{}
		}
	}
	if rec.ElasticsearchJSON != "" {
		var es ElasticsearchSettings
		if err := json.Unmarshal([]byte(rec.ElasticsearchJSON), &es); err == nil {
			currentSettings.Elasticsearch = es
		} else {
			DebugLog("warning: invalid elasticsearch JSON in app_settings, resetting to defaults: %v", err)
			currentSettings.Elasticsearch = ElasticsearchSettings{}
		}
	}
	if rec.ThreatIntelJSON != "" {
		var ti ThreatIntelSettings
		if err := json.Unmarshal([]byte(rec.ThreatIntelJSON), &ti); err == nil {
			currentSettings.ThreatIntel = ti
		} else {
			DebugLog("warning: invalid threat_intel JSON in app_settings, resetting to defaults: %v", err)
			currentSettings.ThreatIntel = ThreatIntelSettings{}
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
			ID:                   rec.ID,
			Name:                 rec.Name,
			Type:                 rec.Type,
			Host:                 rec.Host,
			Port:                 rec.Port,
			SocketPath:           rec.SocketPath,
			ConfigPath:           rec.ConfigPath,
			SSHUser:              rec.SSHUser,
			SSHKeyPath:           rec.SSHKeyPath,
			AgentURL:             rec.AgentURL,
			AgentSecret:          rec.AgentSecret,
			Hostname:             rec.Hostname,
			Tags:                 tags,
			IsDefault:            rec.IsDefault,
			Enabled:              rec.Enabled,
			ReverseTunnelEnabled: rec.ReverseTunnelEnabled,
			TunnelPort:           rec.TunnelPort,
			CreatedAt:            rec.CreatedAt,
			UpdatedAt:            rec.UpdatedAt,
			EnabledSet:           true,
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
	threatIntelBytes, err := json.Marshal(currentSettings.ThreatIntel)
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
		BantimeMaxtime:         currentSettings.BantimeMaxtime,
		BantimeFactor:          currentSettings.BantimeFactor,
		BantimeOveralljails:    currentSettings.BantimeOveralljails,
		AdvancedActionsJSON:    string(advancedBytes),
		GeoIPProvider:          currentSettings.GeoIPProvider,
		GeoIPDatabasePath:      currentSettings.GeoIPDatabasePath,
		MaxLogLines:            currentSettings.MaxLogLines,
		EventRetentionDays:     currentSettings.EventRetentionDays,
		AlertProvider:          alertProvider,
		WebhookJSON:            string(webhookBytes),
		ElasticsearchJSON:      string(esBytes),
		ThreatIntelJSON:        string(threatIntelBytes),
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
			ID:                   srv.ID,
			Name:                 srv.Name,
			Type:                 srv.Type,
			Host:                 srv.Host,
			Port:                 srv.Port,
			SocketPath:           srv.SocketPath,
			ConfigPath:           srv.ConfigPath,
			SSHUser:              srv.SSHUser,
			SSHKeyPath:           srv.SSHKeyPath,
			AgentURL:             srv.AgentURL,
			AgentSecret:          srv.AgentSecret,
			Hostname:             srv.Hostname,
			TagsJSON:             string(tagBytes),
			IsDefault:            srv.IsDefault,
			Enabled:              srv.Enabled,
			ReverseTunnelEnabled: srv.ReverseTunnelEnabled,
			TunnelPort:           srv.TunnelPort,
			CreatedAt:            createdAt,
			UpdatedAt:            updatedAt,
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
	defer refreshLogSecretsLocked()
	setDebugFlag(currentSettings.Debug)
	if currentSettings.Language == "" {
		currentSettings.Language = "en"
	}
	if port, ok := GetPortFromEnv(); ok {
		currentSettings.Port = port
	} else if currentSettings.Port == 0 {
		currentSettings.Port = 8080
	}
	if cbURL := os.Getenv("CALLBACK_URL"); cbURL != "" {
		currentSettings.CallbackURL = strings.TrimRight(strings.TrimSpace(cbURL), "/")
	} else if currentSettings.CallbackURL == "" {
		currentSettings.CallbackURL = defaultCallbackURL(currentSettings.Port)
	} else if isDefaultLoopbackCallbackURL(currentSettings.CallbackURL) {
		currentSettings.CallbackURL = defaultCallbackURL(currentSettings.Port)
	}
	if cbSecret := os.Getenv("CALLBACK_SECRET"); cbSecret != "" {
		currentSettings.CallbackSecret = strings.TrimSpace(cbSecret)
	} else if currentSettings.CallbackSecret == "" {
		currentSettings.CallbackSecret = generateCallbackSecret()
	}
	// Env and BASE_PATH bypass the API validation; action files are refused until these are fixed.
	if err := shared.ValidateCallbackURL(currentSettings.CallbackURL); err != nil {
		log.Printf("ERROR: %v (check CALLBACK_URL / BASE_PATH) - callback action files will not be written until it is fixed", err)
	}
	if err := shared.ValidateCallbackSecret(currentSettings.CallbackSecret); err != nil {
		log.Printf("ERROR: %v (check CALLBACK_SECRET) - callback action files will not be written until it is fixed", err)
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
	scrubLegacySMTPPlaceholders(&currentSettings)
	currentSettings.Elasticsearch.Index = ElasticsearchDataStream(currentSettings.Elasticsearch.Index)
	if currentSettings.SMTP.Port == 0 {
		currentSettings.SMTP.Port = 587
	}
	if currentSettings.SMTP.AuthMethod == "none" {
		currentSettings.SMTP.Username = ""
		currentSettings.SMTP.Password = ""
	}
	if currentSettings.SMTP.AuthMethod == "" {
		currentSettings.SMTP.AuthMethod = "auto"
	}
	for _, warning := range sanitizeJailDefaults(&currentSettings) {
		log.Printf("WARNING: %s", warning)
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
		currentSettings.GeoIPDatabasePath = DefaultGeoIPDatabasePath
	}
	if currentSettings.MaxLogLines == 0 {
		currentSettings.MaxLogLines = 50
	}
	if currentSettings.ThreatIntel.Provider == "" {
		currentSettings.ThreatIntel.Provider = "none"
	}
	if currentSettings.ThreatIntel.Provider != "none" && currentSettings.ThreatIntel.Provider != "alienvault" && currentSettings.ThreatIntel.Provider != "abuseipdb" {
		currentSettings.ThreatIntel.Provider = "none"
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
	settings, err := parseJailDefaults(file)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", jailFile, err)
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
	if val, ok := settings["bantime.maxtime"]; ok && val != "" {
		currentSettings.BantimeMaxtime = val
	}
	if val, ok := settings["bantime.factor"]; ok && val != "" {
		currentSettings.BantimeFactor = val
	}
	if val, ok := settings["bantime.overalljails"]; ok && val != "" {
		currentSettings.BantimeOveralljails = strings.EqualFold(val, "true")
	}
	return nil
}

// Jail sections override these per jail, so only [DEFAULT] feeds the global settings.
func parseJailDefaults(r io.Reader) (map[string]string, error) {
	settings := map[string]string{}
	inDefault := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDefault = strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "DEFAULT")
			continue
		}
		if !inDefault {
			continue
		}
		if m := jailFileKeyValuePattern.FindStringSubmatch(line); m != nil {
			settings[strings.ToLower(m[1])] = m[2]
		}
	}
	return settings, scanner.Err()
}

func normalizeServersLocked() {
	now := time.Now().UTC()
	if len(currentSettings.Servers) == 0 {
		hostname, _ := os.Hostname()
		currentSettings.Servers = []Fail2banServer{{
			ID:         "local",
			Name:       "Fail2ban",
			Type:       "local",
			SocketPath: defaultLocalSocketPath,
			ConfigPath: fail2ban.DefaultConfigRoot,
			Hostname:   hostname,
			IsDefault:  false,
			Enabled:    false,
			CreatedAt:  now,
			UpdatedAt:  now,
			EnabledSet: true,
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
		server.Type = strings.ToLower(strings.TrimSpace(server.Type))
		if server.Type == "" {
			server.Type = "local"
		}
		server.Host = strings.TrimSpace(server.Host)
		server.SSHUser = strings.TrimSpace(server.SSHUser)
		server.SSHKeyPath = normalizePathValue(server.SSHKeyPath)
		server.Name = strings.TrimSpace(server.Name)
		if server.CreatedAt.IsZero() {
			server.CreatedAt = now
		}
		if server.UpdatedAt.IsZero() {
			server.UpdatedAt = now
		}
		if server.Type == "local" {
			server.SocketPath = normalizeLocalSocketPath(server.SocketPath)
			server.ConfigPath = fail2ban.NormalizeConfigPath(server.ConfigPath)
		} else {
			server.SocketPath = normalizePathValue(server.SocketPath)
		}
		if !server.EnabledSet {
			if server.Type == "local" {
				server.Enabled = false
			} else {
				server.Enabled = true
			}
		}
		server.EnabledSet = true
		server.DisabledReason = ""
		server.HostKeyError = ""
		server.HostKeyFingerprint = ""
		if server.Enabled {
			if err := shared.ValidateServerFields(*server); err != nil {
				log.Printf("disabling server %q (%s): invalid configuration: %v - fix and save the server in the UI to re-enable it", server.Name, server.ID, err)
				server.Enabled = false
				server.DisabledReason = err.Error()
			} else if server.Type == "agent" {
				if u, err := fail2ban.NormalizeAgentURL(server.AgentURL); err != nil {
					log.Printf("disabling server %q (%s): invalid agentUrl: %v - fix and save the server in the UI to re-enable it", server.Name, server.ID, err)
					server.Enabled = false
					server.DisabledReason = "invalid agentUrl: " + err.Error()
				} else {
					server.AgentURL = u.String()
				}
			}
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
}

// crypto/rand.Read cannot fail since Go 1.24.
func generateServerID() string {
	var b [8]byte
	rand.Read(b[:])
	return "srv-" + hex.EncodeToString(b[:])
}

func normalizeServerNameKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizePathValue(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return filepath.Clean(trimmed)
}

func normalizeLocalSocketPath(path string) string {
	normalized := normalizePathValue(path)
	if normalized == "" {
		return defaultLocalSocketPath
	}
	return normalized
}

// Validates name and local connector socket/config path collisions.
func validateServerUniqueness(input Fail2banServer, existing []Fail2banServer) error {
	nameKey := normalizeServerNameKey(input.Name)
	socketKey := ""
	configKey := ""
	if input.Type == "local" {
		socketKey = normalizeLocalSocketPath(input.SocketPath)
		configKey = fail2ban.NormalizeConfigPath(input.ConfigPath)
	}

	for _, e := range existing {
		if e.ID == input.ID {
			continue
		}

		if nameKey != "" && normalizeServerNameKey(e.Name) == nameKey {
			return fmt.Errorf("a server with the same name already exists")
		}

		if input.Type != "local" || e.Type != "local" {
			continue
		}

		if normalizeLocalSocketPath(e.SocketPath) == socketKey {
			return fmt.Errorf("a local connector with the same socket path already exists")
		}
		if fail2ban.NormalizeConfigPath(e.ConfigPath) == configKey {
			return fmt.Errorf("a local connector with the same configuration path already exists")
		}
	}

	return nil
}

func validateServerUniquenessLocked(input Fail2banServer) error {
	return validateServerUniqueness(input, currentSettings.Servers)
}

// =========================================================================
//  Fail2ban File Management --> TODO: create a new connector_global.go for functions that are used by all connectors
// =========================================================================

// Builds the content of our fail2ban-UI managed jail.local file. (used by all connectors)
func BuildJailLocalContent() string {
	return buildJailLocalContent(GetSettings())
}

func buildJailLocalContent(settings AppSettings) string {
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
	// bantime.maxtime caps how large escalating bans may grow when
	// bantime.increment is enabled. Only emitted when the operator sets it.
	if settings.BantimeMaxtime != "" {
		defaultSection += fmt.Sprintf("bantime.maxtime = %s\n", settings.BantimeMaxtime)
	}
	if settings.BantimeFactor != "" {
		defaultSection += fmt.Sprintf("bantime.factor = %s\n", settings.BantimeFactor)
	}
	if settings.BantimeOveralljails {
		defaultSection += "bantime.overalljails = true\n"
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

func cloneServer(src Fail2banServer) Fail2banServer {
	dst := src
	if src.Tags != nil {
		dst.Tags = append([]string{}, src.Tags...)
	}
	dst.EnabledSet = src.EnabledSet
	return dst
}

// Builds the content of our fail2ban-UI custom-action file. (used by all connectors)
func BuildFail2banActionConfig(callbackURL, serverID, secret string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	if trimmed == "" || serverID == "" || secret == "" {
		return "", errors.New("callback URL, server ID and secret are required to render the action file")
	}
	// Last line of defence: these values are substituted into a shell command fail2ban runs as root.
	if err := shared.ValidateCallbackURL(trimmed); err != nil {
		return "", err
	}
	if err := shared.ValidateServerID(serverID); err != nil {
		return "", err
	}
	if err := shared.ValidateCallbackSecret(secret); err != nil {
		return "", err
	}
	curlInsecureFlag := ""
	if strings.HasPrefix(strings.ToLower(trimmed), "https://") && shared.CallbackInsecureTLS() {
		curlInsecureFlag = " -k"
	}
	config := strings.ReplaceAll(fail2banActionTemplate, actionCallbackPlaceholder, trimmed)
	config = strings.ReplaceAll(config, actionServerIDPlaceholder, serverID)
	config = strings.ReplaceAll(config, actionSecretPlaceholder, secret)
	config = strings.ReplaceAll(config, actionCurlInsecureFlag, curlInsecureFlag)
	return config, nil
}

// Generates a 42-character random secret for the callback secret.
func generateCallbackSecret() string {
	// Generate first 32 random bytes (256 bits of entropy)
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:42]
}

func getCallbackURLLocked() string {
	url := strings.TrimSpace(currentSettings.CallbackURL)
	if url == "" {
		url = defaultCallbackURL(currentSettings.Port)
	}
	return strings.TrimRight(url, "/")
}

func GetCallbackURL() string {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return getCallbackURLLocked()
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

// ErrInvalidTunnelPort is returned when a reverse-tunnel port is outside the
// unprivileged range. Handlers match it to attach a localized message key.
var ErrInvalidTunnelPort = errors.New("tunnelPort must be between 1024 and 65535 (empty = server port)")

// Reject reverse-tunnel ports outside the unprivileged range
func validateTunnelPort(port int) error {
	if port == 0 || (port >= 1024 && port <= 65535) {
		return nil
	}
	return fmt.Errorf("%w, got %d", ErrInvalidTunnelPort, port)
}

func UpsertServer(input Fail2banServer) (Fail2banServer, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	now := time.Now().UTC()
	input.Type = strings.ToLower(strings.TrimSpace(input.Type))
	input.Host = strings.TrimSpace(input.Host)
	input.SSHUser = strings.TrimSpace(input.SSHUser)
	input.SSHKeyPath = normalizePathValue(input.SSHKeyPath)
	input.DisabledReason = ""
	input.HostKeyError = ""
	input.HostKeyFingerprint = ""
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
	input.Name = strings.TrimSpace(input.Name)
	if !input.EnabledSet {
		if input.Type == "local" {
			input.Enabled = false
		} else {
			input.Enabled = true
		}
		input.EnabledSet = true
	}
	if input.Type == "local" {
		input.SocketPath = normalizeLocalSocketPath(input.SocketPath)
		input.ConfigPath = fail2ban.NormalizeConfigPath(input.ConfigPath)
	} else {
		input.SocketPath = normalizePathValue(input.SocketPath)
		input.ConfigPath = ""
	}
	if input.Type == "ssh" {
		if err := validateTunnelPort(input.TunnelPort); err != nil {
			return Fail2banServer{}, err
		}
	} else {
		input.TunnelPort = 0
	}
	if err := shared.ValidateServerFields(input); err != nil {
		return Fail2banServer{}, err
	}
	if input.Name == "" {
		input.Name = "Fail2ban Server " + input.ID
	}
	if err := validateServerUniquenessLocked(input); err != nil {
		return Fail2banServer{}, err
	}
	replaced := false
	for idx, srv := range currentSettings.Servers {
		if srv.ID == input.ID {
			if !input.EnabledSet {
				input.Enabled = srv.Enabled
				input.EnabledSet = true
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
				srv.EnabledSet = true
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

	config.SkipLoginPage = shared.EnvBool("OIDC_SKIP_LOGINPAGE")
	config.SessionSecret = os.Getenv("OIDC_SESSION_SECRET")

	if config.SessionSecret == "" {
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		config.SessionSecret = base64.URLEncoding.EncodeToString(secretBytes)
	}

	config.SkipVerify = shared.EnvBool("OIDC_SKIP_VERIFY")
	config.UsernameClaim = os.Getenv("OIDC_USERNAME_CLAIM")
	if config.UsernameClaim == "" {
		config.UsernameClaim = "preferred_username"
	}
	config.RoleClaim = os.Getenv("OIDC_ROLE_CLAIM")
	if config.RoleClaim == "" {
		config.RoleClaim = "groups"
	}
	config.AdminRoles = shared.SplitCommaList(os.Getenv("OIDC_ADMIN_ROLES"))
	config.SupportRoles = shared.SplitCommaList(os.Getenv("OIDC_SUPPORT_ROLES"))
	config.AuthorizationEnabled = len(config.AdminRoles) > 0 || len(config.SupportRoles) > 0
	config.LogoutURL = os.Getenv("OIDC_LOGOUT_URL")
	return config, nil
}

// Returns a copy of the current app settings.
func GetSettings() AppSettings {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return cloneSettings(currentSettings)
}

func cloneSettings(s AppSettings) AppSettings {
	s.Servers = append([]Fail2banServer(nil), s.Servers...)
	for i := range s.Servers {
		s.Servers[i] = cloneServer(s.Servers[i])
	}
	s.IgnoreIPs = append([]string(nil), s.IgnoreIPs...)
	s.AlertCountries = append([]string(nil), s.AlertCountries...)
	headers := make(map[string]string, len(s.Webhook.Headers))
	for key, value := range s.Webhook.Headers {
		headers[key] = value
	}
	s.Webhook.Headers = headers
	return s
}

func isDefaultLoopbackCallbackURL(value string) bool {
	return loopbackCallbackURLPattern.MatchString(strings.TrimSuffix(value, shared.BasePath()))
}

// Loopback URL the local fail2ban action uses to reach this UI.
func defaultCallbackURL(port int) string {
	if port == 0 {
		port = 8080
	}
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, shared.BasePath())
}

func UpdateSettings(new AppSettings) (AppSettings, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	DebugLog("--- Locked settings for update ---")
	old := currentSettings
	new.CallbackURL = strings.TrimSpace(new.CallbackURL)
	oldPort := currentSettings.Port
	if new.Port != oldPort && new.Port > 0 {
		if isDefaultLoopbackCallbackURL(new.CallbackURL) || new.CallbackURL == "" {
			new.CallbackURL = defaultCallbackURL(new.Port)
		}
	}
	// Servers change only through UpsertServer/DeleteServer, which validate them.
	new.Servers = make([]Fail2banServer, len(currentSettings.Servers))
	for i, srv := range currentSettings.Servers {
		new.Servers[i] = cloneServer(srv)
	}
	currentSettings = cloneSettings(new)
	setDefaultsLocked()
	DebugLog("Application settings updated")
	if old.ConsoleOutput != new.ConsoleOutput {
		updateConsoleLogState(new.ConsoleOutput)
	}
	if err := persistAllLocked(); err != nil {
		log.Printf("ERROR: saving settings: %v", err)
		return cloneSettings(currentSettings), err
	}
	return cloneSettings(currentSettings), nil
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

// Clears the placeholder SMTP values older releases stored as if they were real configuration.
func scrubLegacySMTPPlaceholders(s *AppSettings) {
	if strings.EqualFold(strings.TrimSpace(s.Destemail), "alerts@example.com") {
		s.Destemail = ""
	}
	if s.SMTP.Username != "noreply@swissmakers.ch" || s.SMTP.Password != "password" {
		return
	}
	s.SMTP.Username = ""
	s.SMTP.Password = ""
	if s.SMTP.Host == "smtp.office365.com" {
		s.SMTP.Host = ""
	}
	if s.SMTP.From == "noreply@swissmakers.ch" {
		s.SMTP.From = ""
	}
}

// Drops stored jail.local defaults that would corrupt the generated [DEFAULT] section.
func sanitizeJailDefaults(s *AppSettings) []string {
	var warnings []string
	kept := make([]string, 0, len(s.IgnoreIPs))
	for _, entry := range s.IgnoreIPs {
		if err := shared.ValidateIgnoreIPEntry(entry); err != nil {
			warnings = append(warnings, fmt.Sprintf("dropping stored ignoreip entry: %v", err))
			continue
		}
		kept = append(kept, entry)
	}
	s.IgnoreIPs = kept
	for _, field := range []*string{&s.Banaction, &s.BanactionAllports} {
		if *field != "" && shared.ValidateBanactionName(*field) != nil {
			warnings = append(warnings, fmt.Sprintf("resetting invalid stored banaction %q to default", *field))
			*field = ""
		}
	}
	if s.Chain != "" && shared.ValidateChainName(s.Chain) != nil {
		warnings = append(warnings, fmt.Sprintf("resetting invalid stored chain %q to default", s.Chain))
		s.Chain = ""
	}
	return warnings
}
