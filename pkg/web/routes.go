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

	// Dashboard at "/" internally; use BASE_PATH env && strip middleware for public subpaths
	r.GET("/", renderIndexPage)

	// API routes group
	api := r.Group("/api")
	{
		// Internal call from frontend to the Fail2ban-UI backend to get the summary of the servers (banned IPs per active jail)
		api.GET("/summary", RequirePermission(PermissionRead), SummaryHandler)

		// External API calls from Fail2ban servers that notify Fail2Ban-UI backend about ban/unban events that where triggered.
		api.POST("/ban", BanNotificationHandler)
		api.POST("/unban", UnbanNotificationHandler)

		// Internal API calls from frontend (e.g. manual actions) to backend to execute Ban / Unban
		api.GET("/jails/:jail/banned", RequirePermission(PermissionRead), ListJailBannedIPsHandler)
		api.POST("/jails/:jail/unban/:ip", RequirePermission(PermissionBan), UnbanIPHandler)
		api.POST("/jails/:jail/ban/:ip", RequirePermission(PermissionBan), BanIPHandler)

		// Search which jails currently ban this IP -> searches on all servers
		api.GET("/ips/:ip/search", RequirePermission(PermissionRead), SearchBannedIPHandler)

		// Internal API calls for jail-filter management
		api.GET("/jails/:jail/config", RequirePermission(PermissionAdmin), GetJailFilterConfigHandler)
		api.POST("/jails/:jail/config", RequirePermission(PermissionAdmin), SetJailFilterConfigHandler)
		api.POST("/jails/:jail/logpath/test", RequirePermission(PermissionAdmin), TestLogpathHandler)
		api.GET("/jails/manage", RequirePermission(PermissionAdmin), ManageJailsHandler)
		api.POST("/jails/manage", RequirePermission(PermissionAdmin), UpdateJailManagementHandler)
		api.POST("/jails", RequirePermission(PermissionAdmin), CreateJailHandler)
		api.DELETE("/jails/:jail", RequirePermission(PermissionAdmin), DeleteJailHandler)

		// Internal API calls for filter management
		api.GET("/filters", RequirePermission(PermissionAdmin), ListFiltersHandler)
		api.GET("/filters/:filter/content", RequirePermission(PermissionAdmin), GetFilterContentHandler)
		api.POST("/filters/test", RequirePermission(PermissionAdmin), TestFilterHandler)
		api.POST("/filters", RequirePermission(PermissionAdmin), CreateFilterHandler)
		api.DELETE("/filters/:filter", RequirePermission(PermissionAdmin), DeleteFilterHandler)

		// Internal API calls for Fail2ban-UI settings
		api.GET("/settings", RequirePermission(PermissionRead), GetSettingsHandler)
		api.POST("/settings", RequirePermission(PermissionAdmin), UpdateSettingsHandler)
		api.POST("/settings/test-email", RequirePermission(PermissionAdmin), TestEmailHandler)
		api.POST("/settings/test-webhook", RequirePermission(PermissionAdmin), TestWebhookHandler)
		api.POST("/settings/test-elasticsearch", RequirePermission(PermissionAdmin), TestElasticsearchHandler)

		// Internal API calls for advanced actions
		api.GET("/advanced-actions/blocks", RequirePermission(PermissionAdmin), ListPermanentBlocksHandler)
		api.DELETE("/advanced-actions/blocks", RequirePermission(PermissionAdmin), ClearPermanentBlocksHandler)
		api.POST("/advanced-actions/test", RequirePermission(PermissionAdmin), AdvancedActionsTestHandler)

		// Internal API calls for Fail2ban-UI server management
		api.GET("/servers", RequirePermission(PermissionRead), ListServersHandler)
		api.POST("/servers", RequirePermission(PermissionAdmin), UpsertServerHandler)
		api.DELETE("/servers/:id", RequirePermission(PermissionAdmin), DeleteServerHandler)
		api.POST("/servers/:id/default", RequirePermission(PermissionAdmin), SetDefaultServerHandler)
		api.GET("/ssh/keys", RequirePermission(PermissionAdmin), ListSSHKeysHandler)
		api.POST("/servers/:id/test", RequirePermission(PermissionAdmin), TestServerHandler)

		// Internal API to restart Fail2ban
		api.POST("/fail2ban/restart", RequirePermission(PermissionAdmin), RestartFail2banHandler)

		// Internal API calls to get the stats and insights about bans
		api.GET("/events/bans", RequirePermission(PermissionRead), ListBanEventsHandler)
		api.DELETE("/events/bans", RequirePermission(PermissionAdmin), ClearBanEventsHandler)
		api.GET("/events/bans/stats", RequirePermission(PermissionRead), BanStatisticsHandler)
		api.GET("/events/bans/insights", RequirePermission(PermissionRead), BanInsightsHandler)
		api.GET("/events/bans/:id", RequirePermission(PermissionRead), GetBanEventHandler)
		api.GET("/threat-intel/:ip", RequirePermission(PermissionRead), ThreatIntelHandler)

		// WebSocket endpoint
		api.GET("/ws", RequirePermission(PermissionRead), WebSocketHandler(hub))

		// API to healthchecks (mainly used by agent)
		api.GET("/healthcheck/callback", HealthcheckCallbackSecret)

		// External API to get the version of the Fail2ban-UI and check for updates
		api.GET("/version", RequirePermission(PermissionRead), GetVersionHandler)
	}
}
