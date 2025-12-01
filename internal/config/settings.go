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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	UseTLS   bool   `json:"useTLS"`
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
	AdvancedActions AdvancedActionsConfig `json:"advancedActions"`

	Servers []Fail2banServer `json:"servers"`

	// Fail2Ban [DEFAULT] section values from jail.local
	BantimeIncrement bool   `json:"bantimeIncrement"`
	IgnoreIP         string `json:"ignoreip"`
	Bantime          string `json:"bantime"`
	Findtime         string `json:"findtime"`
	Maxretry         int    `json:"maxretry"`
	Destemail        string `json:"destemail"`
	//Sender           string `json:"sender"`
}

type AdvancedActionsConfig struct {
	Enabled     bool                        `json:"enabled"`
	Threshold   int                         `json:"threshold"`
	Integration string                      `json:"integration"`
	Mikrotik    MikrotikIntegrationSettings `json:"mikrotik"`
	PfSense     PfSenseIntegrationSettings  `json:"pfSense"`
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
	defaultJailFile           = "/etc/fail2ban/jail.conf"
	jailFile                  = "/etc/fail2ban/jail.local" // Path to jail.local (to override conf-values from jail.conf)
	jailDFile                 = "/etc/fail2ban/jail.d/ui-custom-action.conf"
	actionFile                = "/etc/fail2ban/action.d/ui-custom-action.conf"
	actionCallbackPlaceholder = "__CALLBACK_URL__"
	actionServerIDPlaceholder = "__SERVER_ID__"
)

const fail2banActionTemplate = `[INCLUDES]

before = sendmail-common.conf
         mail-whois-common.conf
         helpers-common.conf

[Definition]

# Bypass ban/unban for restored tickets
norestored = 1

# Option: actionban
# This executes a cURL request to notify our API when an IP is banned.

actionban = /usr/bin/curl -X POST __CALLBACK_URL__/api/ban \
     -H "Content-Type: application/json" \
     -d "$(jq -n --arg serverId '__SERVER_ID__' \
                 --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 --arg failures '<failures>' \
                 --arg whois "$(whois <ip> || echo 'missing whois program')" \
                 --arg logs "$(tac <logpath> | grep <grepopts> -wF <ip>)" \
                 '{serverId: $serverId, ip: $ip, jail: $jail, hostname: $hostname, failures: $failures, whois: $whois, logs: $logs}')"

[Init]

# Default name of the chain
name = default

# Path to log files containing relevant lines for the abuser IP
logpath = /dev/null

# Number of log lines to include in the email
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
	currentSettings.IgnoreIP = rec.IgnoreIP
	currentSettings.Bantime = rec.Bantime
	currentSettings.Findtime = rec.Findtime
	currentSettings.Maxretry = rec.MaxRetry
	currentSettings.Destemail = rec.DestEmail
	currentSettings.SMTP = SMTPSettings{
		Host:     rec.SMTPHost,
		Port:     rec.SMTPPort,
		Username: rec.SMTPUsername,
		Password: rec.SMTPPassword,
		From:     rec.SMTPFrom,
		UseTLS:   rec.SMTPUseTLS,
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
		Language:            currentSettings.Language,
		Port:                currentSettings.Port,
		Debug:               currentSettings.Debug,
		CallbackURL:         currentSettings.CallbackURL,
		RestartNeeded:       currentSettings.RestartNeeded,
		AlertCountriesJSON:  string(countryBytes),
		SMTPHost:            currentSettings.SMTP.Host,
		SMTPPort:            currentSettings.SMTP.Port,
		SMTPUsername:        currentSettings.SMTP.Username,
		SMTPPassword:        currentSettings.SMTP.Password,
		SMTPFrom:            currentSettings.SMTP.From,
		SMTPUseTLS:          currentSettings.SMTP.UseTLS,
		BantimeIncrement:    currentSettings.BantimeIncrement,
		IgnoreIP:            currentSettings.IgnoreIP,
		Bantime:             currentSettings.Bantime,
		Findtime:            currentSettings.Findtime,
		MaxRetry:            currentSettings.Maxretry,
		DestEmail:           currentSettings.Destemail,
		AdvancedActionsJSON: string(advancedBytes),
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
	if currentSettings.IgnoreIP == "" {
		currentSettings.IgnoreIP = "127.0.0.1/8 ::1"
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
		currentSettings.IgnoreIP = val
	}
	if val, ok := settings["destemail"]; ok {
		currentSettings.Destemail = val
	}
	/*if val, ok := settings["sender"]; ok {
		currentSettings.Sender = val
	}*/

	return nil
}

func normalizeServersLocked() {
	now := time.Now().UTC()
	if len(currentSettings.Servers) == 0 {
		hostname, _ := os.Hostname()
		currentSettings.Servers = []Fail2banServer{{
			ID:         "local",
			Name:       "Local Fail2ban",
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

	if err := setupGeoCustomAction(); err != nil {
		return err
	}
	if err := ensureJailDConfig(); err != nil {
		return err
	}
	return writeFail2banAction(callbackURL, serverID)
}

// setupGeoCustomAction checks and replaces the default action in jail.local with our from fail2ban-UI
func setupGeoCustomAction() error {
	DebugLog("Running initial setupGeoCustomAction()") // entry point
	if err := os.MkdirAll(filepath.Dir(jailFile), 0o755); err != nil {
		return fmt.Errorf("failed to ensure jail.local directory: %w", err)
	}

	file, err := os.Open(jailFile)
	if os.IsNotExist(err) {
		if _, statErr := os.Stat(defaultJailFile); os.IsNotExist(statErr) {
			return nil
		}
		if copyErr := copyFile(defaultJailFile, jailFile); copyErr != nil {
			return fmt.Errorf("failed to copy default jail.conf to jail.local: %w", copyErr)
		}
		file, err = os.Open(jailFile)
	}
	if err != nil {
		return err
	}
	defer file.Close()

	var lines []string
	actionPattern := regexp.MustCompile(`^\s*action\s*=\s*%(.*?)\s*$`)
	alreadyModified := false
	actionFound := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check if we already modified the file (prevent duplicate modifications)
		if strings.Contains(line, "# Custom Fail2Ban action applied") {
			alreadyModified = true
		}

		// Look for an existing action definition
		if actionPattern.MatchString(line) && !alreadyModified {
			actionFound = true

			// Comment out the existing action line
			lines = append(lines, "# "+line)

			// Add our replacement action with a comment marker
			lines = append(lines, "# Custom Fail2Ban action applied by fail2ban-ui")
			lines = append(lines, "action = %(action_mwlg)s")
			continue
		}

		// Store the original line
		lines = append(lines, line)
	}

	// If no action was found, no need to modify the file
	if !actionFound || alreadyModified {
		return nil
	}

	// Write back the modified lines
	output := strings.Join(lines, "\n")
	return os.WriteFile(jailFile, []byte(output), 0644)
}

// copyFile copies a file from src to dst. If the destination file does not exist, it will be created.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// ensureJailDConfig checks if the jail.d file exists and creates it if necessary
func ensureJailDConfig() error {
	DebugLog("Running initial ensureJailDConfig()") // entry point
	// Check if the file already exists
	if _, err := os.Stat(jailDFile); err == nil {
		// File already exists, do nothing
		DebugLog("Custom jail.d configuration already exists.")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(jailDFile), 0o755); err != nil {
		return fmt.Errorf("failed to ensure jail.d directory: %v", err)
	}

	// Define the content for the custom jail.d configuration
	jailDConfig := `[DEFAULT]
# Custom Fail2Ban action using geo-filter for email alerts

action_mwlg = %(action_)s
             ui-custom-action[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
`
	// Write the new configuration file
	err := os.WriteFile(jailDFile, []byte(jailDConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write jail.d config: %v", err)
	}

	DebugLog("Created custom jail.d configuration at: %v", jailDFile)
	return nil
}

// writeFail2banAction creates or updates the action file with the AlertCountries.
func writeFail2banAction(callbackURL, serverID string) error {
	DebugLog("Running initial writeFail2banAction()") // entry point
	DebugLog("----------------------------")
	if err := os.MkdirAll(filepath.Dir(actionFile), 0o755); err != nil {
		return fmt.Errorf("failed to ensure action.d directory: %w", err)
	}

	actionConfig := BuildFail2banActionConfig(callbackURL, serverID)
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

func BuildFail2banActionConfig(callbackURL, serverID string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	if trimmed == "" {
		trimmed = "http://127.0.0.1:8080"
	}
	if serverID == "" {
		serverID = "local"
	}
	config := strings.ReplaceAll(fail2banActionTemplate, actionCallbackPlaceholder, trimmed)
	return strings.ReplaceAll(config, actionServerIDPlaceholder, serverID)
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
	restartTriggered := old.BantimeIncrement != new.BantimeIncrement ||
		old.IgnoreIP != new.IgnoreIP ||
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

	if err := persistAllLocked(); err != nil {
		fmt.Println("Error saving settings:", err)
		return currentSettings, err
	}
	return currentSettings, nil
}
