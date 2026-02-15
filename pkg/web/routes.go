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

package web

import (
	"github.com/gin-gonic/gin"
)

// =========================================================================
//  Route Registration
// =========================================================================

func RegisterRoutes(r *gin.Engine, hub *Hub) {
	SetWebSocketHub(hub)

	// Public routes; do not require authentication
	authRoutes := r.Group("/auth")
	{
		authRoutes.GET("/login", LoginHandler)
		authRoutes.GET("/callback", CallbackHandler)
		authRoutes.GET("/logout", LogoutHandler)
		authRoutes.GET("/status", AuthStatusHandler)
		authRoutes.GET("/user", UserInfoHandler)
	}

	// Initialize authentication middleware; all routes below here require authentication
	r.Use(AuthMiddleware())

	// Default currently "/" renders the dashboard -> TODO: To run f2b-UI on a different (sub)-path, we need to prefix that.
	r.GET("/", renderIndexPage)

	// API routes group
	api := r.Group("/api")
	{
		// Internal call from frontend to the Fail2ban-UI backend to get the summary of the servers (banned IPs per active jail)
		api.GET("/summary", SummaryHandler)

		// External API calls from Fail2ban servers that notify Fail2Ban-UI backend about ban/unban events that where triggered.
		api.POST("/ban", BanNotificationHandler)
		api.POST("/unban", UnbanNotificationHandler)

		// Internal API calls from frontend (e.g. manual actions) to backend to execute Ban / Unban
		api.POST("/jails/:jail/unban/:ip", UnbanIPHandler)
		api.POST("/jails/:jail/ban/:ip", BanIPHandler)

		// Internal API calls for jail-filter management (TODO: rename API-call)
		api.GET("/jails/:jail/config", GetJailFilterConfigHandler)
		api.POST("/jails/:jail/config", SetJailFilterConfigHandler)
		api.POST("/jails/:jail/logpath/test", TestLogpathHandler)
		api.GET("/jails/manage", ManageJailsHandler)
		api.POST("/jails/manage", UpdateJailManagementHandler)
		api.POST("/jails", CreateJailHandler)
		api.DELETE("/jails/:jail", DeleteJailHandler)

		// Internal API calls for filter management
		api.GET("/filters", ListFiltersHandler)
		api.GET("/filters/:filter/content", GetFilterContentHandler)
		api.POST("/filters/test", TestFilterHandler)
		api.POST("/filters", CreateFilterHandler)
		api.DELETE("/filters/:filter", DeleteFilterHandler)

		// Internal API calls for Fail2ban-UI settings
		api.GET("/settings", GetSettingsHandler)
		api.POST("/settings", UpdateSettingsHandler)
		api.POST("/settings/test-email", TestEmailHandler)

		// Internal API calls for advanced actions
		api.GET("/advanced-actions/blocks", ListPermanentBlocksHandler)
		api.POST("/advanced-actions/test", AdvancedActionsTestHandler)

		// Internal API calls for Fail2ban-UI server management
		api.GET("/servers", ListServersHandler)
		api.POST("/servers", UpsertServerHandler)
		api.DELETE("/servers/:id", DeleteServerHandler)
		api.POST("/servers/:id/default", SetDefaultServerHandler)
		api.GET("/ssh/keys", ListSSHKeysHandler)
		api.POST("/servers/:id/test", TestServerHandler)

		// Internal API to restart Fail2ban
		api.POST("/fail2ban/restart", RestartFail2banHandler)

		// Internal API calls to get the stats of the bans
		api.GET("/events/bans", ListBanEventsHandler)
		api.GET("/events/bans/stats", BanStatisticsHandler)
		api.GET("/events/bans/insights", BanInsightsHandler)

		// WebSocket endpoint
		api.GET("/ws", WebSocketHandler(hub))

		// Internal & external API to get the version of the Fail2ban-UI and check for updates
		api.GET("/version", GetVersionHandler)
	}
}
