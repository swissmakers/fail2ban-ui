// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package shared

import (
	"encoding/json"
	"time"
)

// Describes a registered Fail2ban instance and how to reach it.
// It lives in package shared so connector code does not import application config.
type Fail2banServer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Host          string    `json:"host,omitempty"`
	Port          int       `json:"port,omitempty"`
	SocketPath    string    `json:"socketPath,omitempty"`
	ConfigPath    string    `json:"configPath,omitempty"`
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
	EnabledSet    bool      `json:"-"`
}

// Distinguishes explicit false for "enabled" from a missing key.
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
		s.EnabledSet = true
	} else {
		s.EnabledSet = false
	}
	return nil
}
