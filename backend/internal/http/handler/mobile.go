package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/zyf2007/ChatAPI/internal/config"
	"github.com/zyf2007/ChatAPI/internal/http/httpx"
	"github.com/zyf2007/ChatAPI/internal/platform/secretbox"
	"github.com/zyf2007/ChatAPI/internal/repository/common"
	"github.com/zyf2007/ChatAPI/internal/service/auth/authz/session"
	"github.com/zyf2007/ChatAPI/internal/service/usercontrol"
)

// MobileHandler deliberately keeps mobile-only configuration out of the public protocol API.
type MobileHandler struct {
	Config      config.Config
	UserControl *usercontrol.Service
	HTTPClient  *http.Client
}

type barkInput struct {
	DeviceKey   string `json:"device_key"`
	Enabled     bool   `json:"enabled"`
	Health      bool   `json:"health"`
	PendingWork bool   `json:"pending_work"`
	Security    bool   `json:"security"`
}

func (h MobileHandler) Capabilities(w http.ResponseWriter, _ *http.Request) {
	// Only advertise shipped capabilities. R2 assets intentionally stay out until
	// uploads and signed URL authorization are implemented end-to-end.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": 1, "features": []string{"bark"}})
}

func (h MobileHandler) Bark(w http.ResponseWriter, r *http.Request) {
	principal, ok := session.PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.UserID) == "" {
		http.Error(w, "session unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, err := h.config(r, principal.UserID)
		if err != nil {
			http.Error(w, "could not load Bark settings", http.StatusInternalServerError)
			return
		}
		ciphertext, _ := value["mobile_bark_key_ciphertext"].(string)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": boolValue(value["mobile_bark_enabled"]), "health": boolValue(value["mobile_bark_health"]), "pending_work": boolValue(value["mobile_bark_pending_work"]), "security": boolValue(value["mobile_bark_security"]), "configured": strings.TrimSpace(ciphertext) != ""})
	case http.MethodPut:
		var input barkInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		value, err := h.config(r, principal.UserID)
		if err != nil {
			http.Error(w, "could not load Bark settings", http.StatusInternalServerError)
			return
		}
		if strings.TrimSpace(input.DeviceKey) != "" {
			sealed, err := secretbox.Seal(strings.TrimSpace(input.DeviceKey), h.Config.MasterKey)
			if err != nil {
				http.Error(w, "could not encrypt device key", http.StatusServiceUnavailable)
				return
			}
			value["mobile_bark_key_ciphertext"] = sealed
		}
		value["mobile_bark_enabled"] = input.Enabled
		value["mobile_bark_health"] = input.Health
		value["mobile_bark_pending_work"] = input.PendingWork
		value["mobile_bark_security"] = input.Security
		ciphertext, _ := value["mobile_bark_key_ciphertext"].(string)
		if input.Enabled && strings.TrimSpace(ciphertext) == "" {
			http.Error(w, "device_key is required when Bark is enabled", http.StatusBadRequest)
			return
		}
		if _, err := h.UserControl.Config.UpdateUserConfig(r.Context(), principal.UserID, value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h MobileHandler) TestBark(w http.ResponseWriter, r *http.Request) {
	principal, ok := session.PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.UserID) == "" {
		http.Error(w, "session unauthorized", http.StatusUnauthorized)
		return
	}
	value, err := h.config(r, principal.UserID)
	if err != nil {
		http.Error(w, "could not load Bark settings", http.StatusInternalServerError)
		return
	}
	sealed, _ := value["mobile_bark_key_ciphertext"].(string)
	sealed = strings.TrimSpace(sealed)
	key, err := secretbox.Open(sealed, h.Config.MasterKey)
	if err != nil || key == "" {
		http.Error(w, "Bark is not configured", http.StatusBadRequest)
		return
	}
	client := h.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := "https://api.day.app/" + url.PathEscape(key) + "/" + url.PathEscape("ChatAPI") + "/" + url.PathEscape("Bark connection successful")
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	response, err := client.Do(req)
	if err != nil || response.StatusCode/100 != 2 {
		if response != nil {
			response.Body.Close()
		}
		http.Error(w, "Bark test failed", http.StatusBadGateway)
		return
	}
	response.Body.Close()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h MobileHandler) config(r *http.Request, userID string) (map[string]any, error) {
	item, err := h.UserControl.Config.GetUserConfig(r.Context(), userID)
	if err != nil {
		if err == common.ErrNotFound {
			return map[string]any{}, nil
		}
		return nil, err
	}
	value := map[string]any{}
	for key, item := range item.Value {
		value[key] = item
	}
	return value, nil
}

func boolValue(value any) bool { result, _ := value.(bool); return result }
