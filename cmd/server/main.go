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

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

// How long in-flight requests get to finish before the process is killed
const shutdownTimeout = 10 * time.Second

// =========================================================================
//  Entrypoint
// =========================================================================

func main() {
	if err := config.Init(""); err != nil {
		log.Fatalf("failed to load settings: %v", err)
	}
	settings := config.GetSettings()

	auth.SetSessionCookiePath(web.CookiePath())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	defer func() {
		if err := storage.Close(); err != nil {
			log.Printf("warning: failed to close storage: %v", err)
		}
	}()

	wsHub := web.NewHub()
	web.SetWebSocketHub(wsHub)
	go wsHub.Run()

	// Restore operation leases before monitors can write to an interrupted target.
	if err := web.PrepareOperations(ctx); err != nil {
		log.Fatalf("failed to prepare background operations: %v", err)
	}

	// Initialize Fail2ban connectors (local filesystem bootstrap and active connectors)
	if err := config.ReloadFail2banManager(); err != nil {
		log.Fatalf("failed to initialise fail2ban connectors: %v", err)
	}

	if err := web.StartOperations(); err != nil {
		log.Fatalf("failed to start background operations: %v", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := web.CloseOperations(closeCtx); err != nil {
			log.Printf("background operation shutdown: %v", err)
		}
	}()

	// Sync local/SSH/agent runtime config and reload so callbacks and defaults become active
	startupSyncDone := make(chan struct{})
	go func() {
		defer close(startupSyncDone)
		manager := fail2ban.GetManager()
		if failed, total := manager.SyncAll(ctx, 30*time.Second), len(manager.Connectors()); total > 0 {
			log.Printf("startup config sync scheduled: %d accepted, %d failed", total-len(failed), len(failed))
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pruneBanEvents()
			}
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

	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/healthz"}}), gin.Recovery())
	serverPort := strconv.Itoa(int(settings.Port))
	bindAddress, _ := config.GetBindAddressFromEnv()
	serverAddr := net.JoinHostPort(bindAddress, serverPort)

	if err := web.MountEmbeddedAssets(router); err != nil {
		log.Fatalf("failed to mount embedded web assets: %v", err)
	}

	// Initialize console log capture
	web.SetupConsoleLogWriter(wsHub)
	web.UpdateConsoleLogEnabled()
	config.SetUpdateConsoleLogStateFunc(web.SetConsoleLogEnabled)

	web.RegisterRoutes(router, wsHub)
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	printWelcomeBanner(bindAddress, serverPort, isLOTRMode)
	if isLOTRMode {
		log.Println("--- Middle-earth Security Realm activated ---")
		log.Println("🎭 LOTR Mode: The guardians of Middle-earth stand ready!")
	} else {
		log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	}
	if bp := shared.BasePath(); bp != "" {
		log.Printf("HTTP base path: %s (from BASE_PATH)\n", bp)
	}
	log.Printf("Server listening on %s:%s.\n", bindAddress, serverPort)

	server := &http.Server{
		Addr:    serverAddr,
		Handler: web.StripBasePathHandler(router),
	}
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		log.Fatalf("Could not start server: %v\n", err)
	case <-ctx.Done():
	}

	// Stop catching signals so a second one kills an unresponsive shutdown
	stop()
	log.Println("Shutdown signal received, stopping Fail2Ban-UI ...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("warning: HTTP server shutdown: %v", err)
	}
	<-startupSyncDone
	if err := web.CloseOperations(shutdownCtx); err != nil {
		log.Printf("background operations will reconcile on restart: %v", err)
	}
	fail2ban.GetManager().Close()
	log.Println("Fail2Ban-UI stopped.")
}

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
