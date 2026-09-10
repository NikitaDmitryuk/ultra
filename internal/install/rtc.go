package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/rtc"
)

// RTCDeployment pins a locally built Linux executable; no provider calls or downloads.
type RTCDeployment struct {
	Binary       string `json:"binary"`
	SHA256       string `json:"sha256"`
	SourceCommit string `json:"source_commit"`
}

func (d RTCDeployment) Validate() error {
	sum, err := hex.DecodeString(d.SHA256)
	if d.Binary == "" || err != nil || len(sum) != 32 || d.SourceCommit != rtc.SourceCommit {
		return errors.New("rtc: binary, sha256 and reviewed source_commit are required")
	}
	return nil
}
func (d RTCDeployment) Verify() error {
	if err := d.Validate(); err != nil {
		return err
	}
	data, err := os.ReadFile(d.Binary)
	if err != nil {
		return errors.New("rtc: binary unavailable")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), d.SHA256) {
		return errors.New("rtc: binary checksum mismatch")
	}
	return nil
}
