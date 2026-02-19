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
	"fmt"
	"log"
	"net"
	"os"
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

	// Initialize storage
	if err := storage.Init(""); err != nil {
		log.Fatalf("Failed to initialise storage: %v", err)
	}
	defer func() {
		if err := storage.Close(); err != nil {
			log.Printf("warning: failed to close storage: %v", err)
		}
	}()

	// Initialize Fail2ban connectors
	if err := fail2ban.GetManager().ReloadFromSettings(settings); err != nil {
		log.Fatalf("failed to initialise fail2ban connectors: %v", err)
	}

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

	// Load templates and static assets based on running in container or locally (compiled binary)
	_, container := os.LookupEnv("CONTAINER")
	if container {
		router.LoadHTMLGlob("/app/templates/*")
		router.Static("/locales", "/app/locales")
		router.Static("/static", "/app/static")
	} else {
		router.LoadHTMLGlob("pkg/web/templates/*")
		router.Static("/locales", "./internal/locales")
		router.Static("/static", "./pkg/web/static")
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
	log.Printf("Server listening on %s:%s.\n", bindAddress, serverPort)

	if err := router.Run(serverAddr); err != nil {
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
