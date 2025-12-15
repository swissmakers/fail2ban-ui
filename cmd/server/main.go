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

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

func main() {
	// Get application settings from the config package.
	settings := config.GetSettings()

	if err := storage.Init(""); err != nil {
		log.Fatalf("Failed to initialise storage: %v", err)
	}
	defer func() {
		if err := storage.Close(); err != nil {
			log.Printf("warning: failed to close storage: %v", err)
		}
	}()

	if err := fail2ban.GetManager().ReloadFromSettings(settings); err != nil {
		log.Fatalf("failed to initialise fail2ban connectors: %v", err)
	}

	// Set Gin mode based on the debug flag in settings.
	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create a new Gin router.
	router := gin.Default()
	serverPort := strconv.Itoa(int(settings.Port))

	// Load HTML templates depending on whether the application is running inside a container.
	_, container := os.LookupEnv("CONTAINER")
	if container {
		// In container, templates are assumed to be in /app/templates
		router.LoadHTMLGlob("/app/templates/*")
		router.Static("/locales", "/app/locales")
		router.Static("/static", "/app/static")
	} else {
		// When running locally, load templates from pkg/web/templates
		router.LoadHTMLGlob("pkg/web/templates/*")
		router.Static("/locales", "./internal/locales")
		router.Static("/static", "./pkg/web/static")
	}

	// Initialize WebSocket hub
	wsHub := web.NewHub()
	go wsHub.Run()

	// Register all application routes, including the static files and templates.
	web.RegisterRoutes(router, wsHub)

	// Check if LOTR mode is active
	isLOTRMode := isLOTRModeActive(settings.AlertCountries)
	printWelcomeBanner(serverPort, isLOTRMode)
	if isLOTRMode {
		log.Println("--- Middle-earth Security Realm activated ---")
		log.Println("🎭 LOTR Mode: The guardians of Middle-earth stand ready!")
	} else {
		log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	}
	log.Println("Server listening on port", serverPort, ".")

	// Start the server on port 8080.
	if err := router.Run(":" + serverPort); err != nil {
		log.Fatalf("Could not start server: %v\n", err)
	}
}

func isLOTRModeActive(alertCountries []string) bool {
	if len(alertCountries) == 0 {
		return false
	}
	for _, country := range alertCountries {
		if strings.EqualFold(country, "LOTR") {
			return true
		}
	}
	return false
}

// printWelcomeBanner prints the Tux banner with startup info.
func printWelcomeBanner(appPort string, isLOTRMode bool) {
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
Listening on: http://0.0.0.0:%s
══════════════════════════════════════════════════

`
		fmt.Printf(lotrBanner, greeting, gin.Mode(), appPort)
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
Listening on: http://0.0.0.0:%s
----------------------------------------------

`
		fmt.Printf(tuxBanner, greeting, gin.Mode(), appPort)
	}
}

// getGreeting returns a friendly greeting based on the time of day.
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
