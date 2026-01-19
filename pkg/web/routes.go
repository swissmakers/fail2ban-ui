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

package web

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes sets up the routes for the Fail2ban UI.
func RegisterRoutes(r *gin.Engine, hub *Hub) {
	// Set the global WebSocket hub
	SetWebSocketHub(hub)

	// Public authentication routes (no auth required)
	authRoutes := r.Group("/auth")
	{
		authRoutes.GET("/login", LoginHandler)
		authRoutes.GET("/callback", CallbackHandler)
		authRoutes.GET("/logout", LogoutHandler)
		authRoutes.GET("/status", AuthStatusHandler)
		authRoutes.GET("/user", UserInfoHandler)
	}

	// Apply authentication middleware to all routes
	r.Use(AuthMiddleware())

	// Render the dashboard
	r.GET("/", renderIndexPage)

	api := r.Group("/api")
	{
		api.GET("/summary", SummaryHandler)
		api.POST("/jails/:jail/unban/:ip", UnbanIPHandler)
		api.POST("/jails/:jail/ban/:ip", BanIPHandler)

		// Routes for jail-filter management (TODO: rename API-call)
		api.GET("/jails/:jail/config", GetJailFilterConfigHandler)
		api.POST("/jails/:jail/config", SetJailFilterConfigHandler)
		api.POST("/jails/:jail/logpath/test", TestLogpathHandler)

		// Routes for jail management
		api.GET("/jails/manage", ManageJailsHandler)
		api.POST("/jails/manage", UpdateJailManagementHandler)
		api.POST("/jails", CreateJailHandler)
		api.DELETE("/jails/:jail", DeleteJailHandler)

		// Settings endpoints
		api.GET("/settings", GetSettingsHandler)
		api.POST("/settings", UpdateSettingsHandler)
		api.POST("/settings/test-email", TestEmailHandler)
		api.GET("/advanced-actions/blocks", ListPermanentBlocksHandler)
		api.POST("/advanced-actions/test", AdvancedActionsTestHandler)

		// Fail2ban servers management
		api.GET("/servers", ListServersHandler)
		api.POST("/servers", UpsertServerHandler)
		api.DELETE("/servers/:id", DeleteServerHandler)
		api.POST("/servers/:id/default", SetDefaultServerHandler)
		api.GET("/ssh/keys", ListSSHKeysHandler)
		api.POST("/servers/:id/test", TestServerHandler)

		// Filter debugger endpoints
		api.GET("/filters", ListFiltersHandler)
		api.GET("/filters/:filter/content", GetFilterContentHandler)
		api.POST("/filters/test", TestFilterHandler)
		api.POST("/filters", CreateFilterHandler)
		api.DELETE("/filters/:filter", DeleteFilterHandler)

		// Restart endpoint
		api.POST("/fail2ban/restart", RestartFail2banHandler)

		// Handle Fail2Ban notifications
		api.POST("/ban", BanNotificationHandler)
		api.POST("/unban", UnbanNotificationHandler)

		// Internal database overview
		api.GET("/events/bans", ListBanEventsHandler)
		api.GET("/events/bans/stats", BanStatisticsHandler)
		api.GET("/events/bans/insights", BanInsightsHandler)

		// WebSocket endpoint
		api.GET("/ws", WebSocketHandler(hub))
	}
}
