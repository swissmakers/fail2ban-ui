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

package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type unifiIntegration struct {
	mu       sync.Mutex
	baseURL  string
	siteName string
	siteID   string
}

type unifiTrafficMatchingListResponse struct {
	Data []unifiTrafficMatchingListSummary `json:"data"`
}

type unifiSitesResponse struct {
	Data []unifiSite `json:"data"`
}

type unifiTrafficMatchingListSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type unifiTrafficMatchingList struct {
	ID    string                     `json:"id"`
	Name  string                     `json:"name"`
	Type  string                     `json:"type"`
	Items []unifiTrafficMatchingItem `json:"items"`
}

type unifiTrafficMatchingItem struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type unifiSite struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func init() {
	Register(&unifiIntegration{})
}

func (u *unifiIntegration) ID() string {
	return "unifi"
}

func (u *unifiIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if err := ValidateOutboundURL(cfg.UniFi.BaseURL, "UniFi base URL"); err != nil {
		return err
	}

	if cfg.UniFi.APIKey == "" {
		return fmt.Errorf("UniFi API key is required")
	}

	if err := ValidateIdentifier(cfg.UniFi.SiteName, "UniFi site name"); err != nil {
		return err
	}

	if err := ValidateIdentifier(cfg.UniFi.TrafficListName, "UniFi traffic matching list name"); err != nil {
		return err
	}

	return nil
}

func (u *unifiIntegration) BlockIP(req Request) error {
	if err := u.Validate(req.Config); err != nil {
		return err
	}

	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("unifi block: %w", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	list, err := u.findList(req)

	if err != nil {
		return err
	}

	if list == nil {
		if req.Logger != nil {
			req.Logger(
				"UniFi traffic matching list %s not found, creating it with IP %s",
				req.Config.UniFi.TrafficListName,
				req.IP,
			)
		}

		return u.createList(req, req.IP)
	}

	if list.Type != "IPV4_ADDRESSES" {
		return fmt.Errorf(
			"UniFi traffic matching list %s is type %s, expected IPV4_ADDRESSES",
			list.Name,
			list.Type,
		)
	}

	for _, item := range list.Items {
		if item.Type == "IP_ADDRESS" && item.Value == req.IP {
			if req.Logger != nil {
				req.Logger(
					"IP %s already exists in UniFi traffic matching list %s",
					req.IP,
					list.Name,
				)
			}

			return nil
		}
	}

	list.Items = append(list.Items, unifiTrafficMatchingItem{
		Type:  "IP_ADDRESS",
		Value: req.IP,
	})

	return u.updateList(req, list)
}

func (u *unifiIntegration) UnblockIP(req Request) error {
	if err := u.Validate(req.Config); err != nil {
		return err
	}

	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("unifi unblock: %w", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	list, err := u.findList(req)

	if err != nil {
		return err
	}

	if list == nil {
		return fmt.Errorf(
			"UniFi traffic matching list %s does not exist",
			req.Config.UniFi.TrafficListName,
		)
	}

	if list.Type != "IPV4_ADDRESSES" {
		return fmt.Errorf(
			"UniFi traffic matching list %s is type %s, expected IPV4_ADDRESSES",
			list.Name,
			list.Type,
		)
	}

	found := false

	items := make([]unifiTrafficMatchingItem, 0, len(list.Items))

	for _, item := range list.Items {
		if item.Type == "IP_ADDRESS" && item.Value == req.IP {
			found = true
			continue
		}

		items = append(items, item)
	}

	if !found {
		if req.Logger != nil {
			req.Logger(
				"IP %s not found in UniFi traffic matching list %s",
				req.IP,
				list.Name,
			)
		}

		return nil
	}

	if len(items) == 0 {
		return fmt.Errorf(
			"cannot remove %s because UniFi traffic matching lists require at least one item",
			req.IP,
		)
	}

	list.Items = items

	return u.updateList(req, list)
}

func (u *unifiIntegration) getSiteID(req Request) (string, error) {
	cfg := req.Config.UniFi

	if u.baseURL == cfg.BaseURL && u.siteName == cfg.SiteName && u.siteID != "" {
		return u.siteID, nil
	}

	apiURL, err := u.buildURL(cfg, "sites")
	if err != nil {
		return "", err
	}

	client := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	httpReq, err := http.NewRequestWithContext(
		req.Context,
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create UniFi request: %w", err)
	}

	u.setHeaders(httpReq, cfg.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("UniFi API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read UniFi API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"UniFi API returned %s: %s",
			resp.Status,
			strings.TrimSpace(string(body)),
		)
	}

	var sites unifiSitesResponse

	if err := json.Unmarshal(body, &sites); err != nil {
		return "", fmt.Errorf("failed to decode UniFi sites: %w", err)
	}

	for _, site := range sites.Data {
		if strings.EqualFold(site.Name, cfg.SiteName) {
			u.baseURL = cfg.BaseURL
			u.siteName = cfg.SiteName
			u.siteID = site.ID

			return site.ID, nil
		}
	}

	return "", fmt.Errorf("UniFi site %q was not found", cfg.SiteName)
}

func (u *unifiIntegration) findList(
	req Request,
) (*unifiTrafficMatchingList, error) {
	cfg := req.Config.UniFi

	siteID, err := u.getSiteID(req)
	if err != nil {
		return nil, err
	}

	apiURL, err := u.buildURL(
		cfg,
		"sites",
		siteID,
		"traffic-matching-lists",
	)
	if err != nil {
		return nil, err
	}

	client := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	httpReq, err := http.NewRequestWithContext(
		req.Context,
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create UniFi request: %w", err)
	}

	u.setHeaders(httpReq, cfg.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("UniFi API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read UniFi API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"UniFi API returned %s: %s",
			resp.Status,
			strings.TrimSpace(string(body)),
		)
	}

	var result unifiTrafficMatchingListResponse

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf(
			"failed to decode UniFi traffic matching lists response: %w",
			err,
		)
	}

	for _, list := range result.Data {
		if list.Name != cfg.TrafficListName {
			continue
		}

		if list.Type != "IPV4_ADDRESSES" {
			return nil, fmt.Errorf(
				"UniFi traffic matching list %s is type %s, expected IPV4_ADDRESSES",
				list.Name,
				list.Type,
			)
		}

		return u.getList(req, list.ID)
	}

	return nil, nil
}

func (u *unifiIntegration) getList(
	req Request,
	listID string,
) (*unifiTrafficMatchingList, error) {
	cfg := req.Config.UniFi

	siteID, err := u.getSiteID(req)
	if err != nil {
		return nil, err
	}

	apiURL, err := u.buildURL(
		cfg,
		"sites",
		siteID,
		"traffic-matching-lists",
		listID,
	)
	if err != nil {
		return nil, err
	}

	client := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	httpReq, err := http.NewRequestWithContext(
		req.Context,
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create UniFi request: %w", err)
	}

	u.setHeaders(httpReq, cfg.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("UniFi API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read UniFi API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"UniFi API returned %s: %s",
			resp.Status,
			strings.TrimSpace(string(body)),
		)
	}

	var result unifiTrafficMatchingList

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf(
			"failed to decode UniFi traffic matching list response: %w",
			err,
		)
	}

	return &result, nil
}

func (u *unifiIntegration) createList(req Request, ip string) error {
	cfg := req.Config.UniFi
	siteID, err := u.getSiteID(req)
	if err != nil {
		return err
	}

	apiURL, err := u.buildURL(
		cfg,
		"sites",
		siteID,
		"traffic-matching-lists",
	)
	if err != nil {
		return err
	}

	payload := struct {
		Type  string                     `json:"type"`
		Name  string                     `json:"name"`
		Items []unifiTrafficMatchingItem `json:"items"`
	}{
		Type: "IPV4_ADDRESSES",
		Name: cfg.TrafficListName,
		Items: []unifiTrafficMatchingItem{
			{
				Type:  "IP_ADDRESS",
				Value: ip,
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode UniFi payload: %w", err)
	}

	client := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	httpReq, err := http.NewRequestWithContext(
		req.Context,
		http.MethodPost,
		apiURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	u.setHeaders(httpReq, cfg.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("UniFi API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf(
			"failed to create UniFi traffic matching list: status %s, response: %s",
			resp.Status,
			strings.TrimSpace(string(body)),
		)
	}

	if req.Logger != nil {
		req.Logger(
			"Created UniFi traffic matching list %s with IP %s",
			cfg.TrafficListName,
			ip,
		)
	}

	return nil
}

func (u *unifiIntegration) updateList(
	req Request,
	list *unifiTrafficMatchingList,
) error {
	cfg := req.Config.UniFi
	siteID, err := u.getSiteID(req)
	if err != nil {
		return err
	}

	apiURL, err := u.buildURL(
		cfg,
		"sites",
		siteID,
		"traffic-matching-lists",
		list.ID,
	)
	if err != nil {
		return err
	}

	payload := struct {
		Type  string                     `json:"type"`
		Name  string                     `json:"name"`
		Items []unifiTrafficMatchingItem `json:"items"`
	}{
		Type:  list.Type,
		Name:  list.Name,
		Items: list.Items,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	client := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	httpReq, err := http.NewRequestWithContext(
		req.Context,
		http.MethodPut,
		apiURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	u.setHeaders(httpReq, cfg.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf(
			"failed to update UniFi traffic matching list: status %s, response: %s",
			resp.Status,
			strings.TrimSpace(string(body)),
		)
	}

	return nil
}

func (u *unifiIntegration) buildURL(
	cfg config.UniFiIntegrationSettings,
	parts ...string,
) (string, error) {
	base, err := url.Parse(strings.TrimSuffix(cfg.BaseURL, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid UniFi base URL: %w", err)
	}

	path := []string{
		"proxy",
		"network",
		"integration",
		"v1",
	}

	path = append(path, parts...)

	return base.JoinPath(path...).String(), nil
}

func (u *unifiIntegration) setHeaders(req *http.Request, apiKey string) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", apiKey)
}
