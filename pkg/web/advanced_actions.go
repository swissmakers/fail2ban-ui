package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

func evaluateAdvancedActions(ctx context.Context, settings config.AppSettings, server config.Fail2banServer, ip string) {
	cfg := settings.AdvancedActions
	if !cfg.Enabled || cfg.Threshold <= 0 || cfg.Integration == "" {
		return
	}

	count, err := storage.CountBanEventsByIP(ctx, ip, server.ID)
	if err != nil {
		log.Printf("⚠️ Failed to count ban events for %s: %v", ip, err)
		return
	}
	if int(count) < cfg.Threshold {
		return
	}

	active, err := storage.IsPermanentBlockActive(ctx, ip, cfg.Integration)
	if err != nil {
		log.Printf("⚠️ Failed to check permanent block for %s: %v", ip, err)
		return
	}
	if active {
		return
	}

	if err := runAdvancedIntegrationAction(ctx, "block", ip, settings, server, map[string]any{
		"reason":    "automatic_threshold",
		"count":     count,
		"threshold": cfg.Threshold,
	}, false); err != nil {
		log.Printf("⚠️ Failed to permanently block %s: %v", ip, err)
	}
}

func runAdvancedIntegrationAction(ctx context.Context, action, ip string, settings config.AppSettings, server config.Fail2banServer, details map[string]any, skipLoggingIfAlreadyBlocked bool) error {
	cfg := settings.AdvancedActions
	if cfg.Integration == "" {
		return fmt.Errorf("no integration configured")
	}
	integration, ok := integrations.Get(cfg.Integration)
	if !ok {
		return fmt.Errorf("integration %s not registered", cfg.Integration)
	}

	logger := func(format string, args ...interface{}) {
		if settings.Debug {
			log.Printf(format, args...)
		}
	}

	req := integrations.Request{
		Context: ctx,
		IP:      ip,
		Config:  cfg,
		Server:  server,
		Logger:  logger,
	}

	var err error
	switch action {
	case "block":
		err = integration.BlockIP(req)
	case "unblock":
		err = integration.UnblockIP(req)
	default:
		return fmt.Errorf("unsupported action %s", action)
	}

	status := map[string]string{
		"block":   "blocked",
		"unblock": "unblocked",
	}[action]

	message := fmt.Sprintf("%s via %s", cases.Title(language.English).String(action), cfg.Integration)
	if err != nil && !skipLoggingIfAlreadyBlocked {
		status = "error"
		message = err.Error()
	}

	// If IP is already blocked, don't update the database entry - leave existing entry as is
	if !skipLoggingIfAlreadyBlocked {
		if details == nil {
			details = map[string]any{}
		}
		details["action"] = action
		detailsBytes, _ := json.Marshal(details)
		rec := storage.PermanentBlockRecord{
			IP:          ip,
			Integration: cfg.Integration,
			Status:      status,
			Message:     message,
			ServerID:    server.ID,
			Details:     string(detailsBytes),
		}
		if err2 := storage.UpsertPermanentBlock(ctx, rec); err2 != nil {
			log.Printf("⚠️ Failed to record permanent block entry: %v", err2)
		}
	}

	return err
}
