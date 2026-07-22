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

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

// =========================================================================
//  Entrypoint
// =========================================================================

func main() {
	settings := config.GetSettings()

	web.SetBasePathFromEnv()
	auth.SetSessionCookiePath(web.CookiePath())

	if err := storage.Init(""); err != nil {
		log.Fatalf("Failed to initialise storage: %v", err)
	}
	defer func() {
		if err := storage.Close(); err != nil {
			log.Printf("warning: failed to close storage: %v", err)
		}
	}()

	// Initialize Fail2ban connectors (local filesystem bootstrap and active connectors)
	if err := config.ReloadFail2banManager(); err != nil {
		log.Fatalf("failed to initialise fail2ban connectors: %v", err)
	}

	// Sync remote SSH/agent runtime config, then reload so action/callback and jail.local changes become active
	go func() {
		synced, failed := fail2ban.GetManager().SyncRemoteStartupConfig(context.Background(), 30*time.Second)
		if synced+failed > 0 {
			log.Printf("startup remote config sync complete: %d succeeded, %d failed", synced, failed)
		}
	}()

	// Prune ban events beyond the configured retention window once at startup and then daily
	go func() {
		pruneBanEvents := func() {
			retentionDays := config.GetSettings().EventRetentionDays
			if retentionDays <= 0 {
				return
			}
			cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			deleted, err := storage.PruneBanEventsBefore(ctx, cutoff)
			cancel()
			if err != nil {
				log.Printf("warning: failed to prune ban events older than %d days: %v", retentionDays, err)
				return
			}
			if deleted > 0 {
				log.Printf("Pruned %d ban events older than %d days", deleted, retentionDays)
			}
		}
		pruneBanEvents()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			pruneBanEvents()
		}
	}()

	// Initialize OIDC authentication
	oidcConfig, err := config.GetOIDCConfigFromEnv()
	if err != nil {
		log.Fatalf("failed to load OIDC configuration: %v", err)
	}
	if oidcConfig != nil && oidcConfig.Enabled {
		if err := auth.InitializeSessionSecret(oidcConfig.SessionSecret); err != nil {
			log.Fatalf("failed to initialize session secret: %v", err)
		}
		if _, err := auth.InitializeOIDC(oidcConfig); err != nil {
			log.Fatalf("failed to initialize OIDC: %v", err)
		}
		log.Println("OIDC authentication enabled")
	} else {
		log.Println("WARNING: OIDC authentication is DISABLED -> Run this way only in a trusted network or behind an authenticating reverse proxy (see docs/security.md).")
	}

	// Set Gin mode
	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.Default()
	serverPort := strconv.Itoa(int(settings.Port))
	bindAddress, _ := config.GetBindAddressFromEnv()
	serverAddr := net.JoinHostPort(bindAddress, serverPort)

	if err := web.MountEmbeddedAssets(router); err != nil {
		log.Fatalf("failed to mount embedded web assets: %v", err)
	}

	// Initialize WebSocket hub and console log capture
	wsHub := web.NewHub()
	go wsHub.Run()
	web.SetupConsoleLogWriter(wsHub)
	web.UpdateConsoleLogEnabled()
	config.SetUpdateConsoleLogStateFunc(func(enabled bool) {
		web.SetConsoleLogEnabled(enabled)
	})

	// Register routes
	web.RegisterRoutes(router, wsHub)
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	printWelcomeBanner(bindAddress, serverPort, isLOTRMode)
	if isLOTRMode {
		log.Println("--- Middle-earth Security Realm activated ---")
		log.Println("🎭 LOTR Mode: The guardians of Middle-earth stand ready!")
	} else {
		log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	}
	if bp := web.BasePath(); bp != "" {
		log.Printf("HTTP base path: %s (from BASE_PATH)\n", bp)
	}
	log.Printf("Server listening on %s:%s.\n", bindAddress, serverPort)

	server := &http.Server{
		Addr:    serverAddr,
		Handler: web.StripBasePathHandler(router),
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Could not start server: %v\n", err)
	}
}

// Print welcome banner.
func printWelcomeBanner(bindAddress, appPort string, isLOTRMode bool) {
	greeting := getGreeting()

	if isLOTRMode {
		const lotrBanner = `
      .--.
     |o_o |     %s
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/'\
  \___)=(___/

Middle-earth Security Realm - LOTR Mode Activated
══════════════════════════════════════════════════
⚔️  The guardians of Middle-earth stand ready!  ⚔️
Developers:   https://swissmakers.ch
Mode:         %s
Listening on: http://%s:%s
══════════════════════════════════════════════════

`
		fmt.Printf(lotrBanner, greeting, gin.Mode(), bindAddress, appPort)
	} else {
		const tuxBanner = `
      .--.
     |o_o |     %s
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/'\
  \___)=(___/

Fail2Ban UI - A Swissmade Management Interface
----------------------------------------------
Developers:   https://swissmakers.ch
Mode:         %s
Listening on: http://%s:%s
----------------------------------------------

`
		fmt.Printf(tuxBanner, greeting, gin.Mode(), bindAddress, appPort)
	}
}

func getGreeting() string {
	hour := time.Now().Hour()
	switch {
	case hour < 12:
		return "Good morning!"
	case hour < 18:
		return "Good afternoon!"
	default:
		return "Good evening!"
	}
}
