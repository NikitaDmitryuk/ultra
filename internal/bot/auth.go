package bot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidInitData is returned when Telegram initData fails HMAC validation.
var ErrInvalidInitData = errors.New("bot: invalid initData")

// ErrExpiredInitData is returned when Telegram initData is older than 24 hours.
var ErrExpiredInitData = errors.New("bot: expired initData")

// TelegramUser is the authenticated user extracted from Telegram WebApp initData.
type TelegramUser struct {
	ID           int64  `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username"`
	LanguageCode string `json:"language_code"`
}

// DisplayName returns the best available display name for the user.
func (u TelegramUser) DisplayName() string {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name != "" {
		return name
	}
	if u.Username != "" {
		return "@" + u.Username
	}
	return strconv.FormatInt(u.ID, 10)
}

// ValidateInitData parses and validates the raw Telegram WebApp initData string.
// It checks the HMAC signature and that the auth_date is within the last 24 hours.
// Returns the authenticated TelegramUser on success.
func ValidateInitData(rawInitData, botToken string) (TelegramUser, error) {
	vals, err := url.ParseQuery(rawInitData)
	if err != nil || len(vals) == 0 {
		return TelegramUser{}, ErrInvalidInitData
	}
	hash := vals.Get("hash")
	if hash == "" {
		return TelegramUser{}, ErrInvalidInitData
	}

	// Build the data-check-string: sorted "key=value" pairs (excluding "hash"), joined by "\n".
	pairs := make([]string, 0, len(vals)-1)
	for k, v := range vals {
		if k == "hash" {
			continue
		}
		pairs = append(pairs, k+"="+v[0])
	}
	sort.Strings(pairs)
	dataCheckString := strings.Join(pairs, "\n")

	// secret_key = HMAC-SHA256(key="WebAppData", data=botToken)
	h := hmac.New(sha256.New, []byte("WebAppData"))
	h.Write([]byte(botToken))
	secretKey := h.Sum(nil)

	// computed_hash = HMAC-SHA256(key=secretKey, data=dataCheckString)
	h2 := hmac.New(sha256.New, secretKey)
	h2.Write([]byte(dataCheckString))
	computed := hex.EncodeToString(h2.Sum(nil))

	if !hmac.Equal([]byte(computed), []byte(hash)) {
		return TelegramUser{}, ErrInvalidInitData
	}

	// Reject stale sessions (max 24 hours).
	if authDateStr := vals.Get("auth_date"); authDateStr != "" {
		authDate, parseErr := strconv.ParseInt(authDateStr, 10, 64)
		if parseErr == nil && time.Now().Unix()-authDate > 86400 {
			return TelegramUser{}, ErrExpiredInitData
		}
	}

	userJSON := vals.Get("user")
	if userJSON == "" {
		return TelegramUser{}, ErrInvalidInitData
	}
	var user TelegramUser
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
		return TelegramUser{}, ErrInvalidInitData
	}
	return user, nil
}
