package installplan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func (p *InstallPlan) SecretsEnvFile() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.Secrets.EnvFile); s != "" {
		return s
	}
	if s := strings.TrimSpace(p.Bot.EnvFile); s != "" {
		return s
	}
	return ".env"
}

// ReadDatabaseCredentials accepts an operator-owned saved bridge spec. It never
// exports its DSN into the canonical non-secret deployment configuration.
func ReadDatabaseCredentials(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("database credentials file must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("database credentials file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) {
		return "", fmt.Errorf("database credentials file changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1048577))
	if err != nil || len(data) > 1048576 {
		return "", fmt.Errorf("database credentials file exceeds bounds")
	}
	var saved struct {
		Database *struct {
			DSN string `json:"dsn"`
		} `json:"database"`
	}
	if json.Unmarshal(data, &saved) != nil || saved.Database == nil || saved.Database.DSN == "" {
		return "", fmt.Errorf("database credentials file requires a saved bridge spec")
	}
	return saved.Database.DSN, nil
}
