// Package bark delivers mobile push notifications to a user's Bark device.
// It is deliberately separate from the HTTP handler: the handler only stores
// encrypted preferences while this package is the runtime delivery path.
package bark

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zyf2007/ChatAPI/internal/ops/observability/logging"
	"github.com/zyf2007/ChatAPI/internal/platform/secretbox"
	"github.com/zyf2007/ChatAPI/internal/repository/common"
	configrepo "github.com/zyf2007/ChatAPI/internal/repository/config"
	"go.uber.org/zap"
)

const (
	settingsKey  = "settings"
	maxBodyRunes = 280
)

// Service sends best-effort pending-work pushes. Notification delivery never
// blocks the chat request path and device keys are decrypted only in memory.
type Service struct {
	configs   configrepo.Store
	masterKey string
	client    *http.Client
	logger    *zap.Logger
}

func New(configs configrepo.Store, masterKey string, client *http.Client, logger *zap.Logger) *Service {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Service{configs: configs, masterKey: masterKey, client: client, logger: logger}
}

// NotifyWaiting satisfies turn.SubmitHooks. Work runs in a bounded detached
// context because the originating HTTP request normally ends before delivery.
func (s *Service) NotifyWaiting(_ context.Context, ownerID, title, userText string) {
	if s == nil || s.configs == nil || strings.TrimSpace(ownerID) == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		s.send(ctx, strings.TrimSpace(ownerID), title, userText)
	}()
}

func (s *Service) send(ctx context.Context, ownerID, title, userText string) {
	item, err := s.configs.GetUserConfig(ctx, ownerID, settingsKey)
	if err != nil {
		if err != common.ErrNotFound {
			s.log(ctx, "Bark settings lookup failed", ownerID, err)
		}
		return
	}
	value := item.Value
	if !asBool(value["mobile_bark_enabled"]) || !asBool(value["mobile_bark_pending_work"]) {
		return
	}
	sealed, _ := value["mobile_bark_key_ciphertext"].(string)
	key, err := secretbox.Open(strings.TrimSpace(sealed), s.masterKey)
	if err != nil || strings.TrimSpace(key) == "" {
		s.log(ctx, "Bark key unavailable", ownerID, err)
		return
	}
	if strings.TrimSpace(title) == "" {
		title = "ChatAPI"
	}
	body := strings.TrimSpace(userText)
	if body == "" {
		body = "收到一条新的模型调用请求，请打开工作台回复。"
	}
	body = truncateRunes(body, maxBodyRunes)
	endpoint := "https://api.day.app/" + url.PathEscape(key) + "/" + url.PathEscape(title) + "/" + url.PathEscape(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		s.log(ctx, "Bark request build failed", ownerID, err)
		return
	}
	response, err := s.client.Do(req)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		s.log(ctx, "Bark send failed", ownerID, err)
		return
	}
	if response.StatusCode/100 != 2 {
		s.log(ctx, "Bark send rejected", ownerID, nil)
	}
}

func (s *Service) log(ctx context.Context, message, ownerID string, err error) {
	if s.logger == nil {
		return
	}
	fields := []zap.Field{zap.String("owner.id", ownerID)}
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	logging.BindContext(s.logger, ctx, fields...).Debug(message)
}

func asBool(value any) bool { result, _ := value.(bool); return result }

func truncateRunes(value string, limit int) string {
	chars := []rune(value)
	if len(chars) <= limit {
		return value
	}
	return string(chars[:limit]) + "…"
}
