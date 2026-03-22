package mimic

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func init() {
	Register("steamlike", func() (Strategy, error) { return NewSteamlike(), nil })
}

// DefaultSteamlikeHost is the default HTTP Host and TLS name hint when spec.splithttp_host is unset.
// Override splithttp_host (and tunnel TLS) when using a certificate issued for your own FQDN.
const DefaultSteamlikeHost = "client-download.steampowered.com"

// Steamlike is an HTTP template for bridge→exit splithttp: request-line path shapes and headers
// aligned with common game-platform Web API and depot/CDN URL patterns (structure only).
type Steamlike struct{}

func NewSteamlike() *Steamlike { return &Steamlike{} }

func (p *Steamlike) Name() string { return "steamlike" }

func (p *Steamlike) Host() string { return DefaultSteamlikeHost }

func (p *Steamlike) NextPath() string {
	var u [8]byte
	_, _ = rand.Read(u[:])
	w := binary.LittleEndian.Uint64(u[:])
	switch w % 5 {
	case 0, 1:
		apis := []string{
			"/ISteamApps/GetAppList/v2/",
			"/IPlayerService/GetOwnedGames/v1/",
			"/ISteamUser/GetPlayerSummaries/v0002/",
			"/ISteamNews/GetNewsForApp/v0002/",
		}
		return apis[(w>>8)%uint64(len(apis))]
	case 2, 3:
		var depot [2]byte
		_, _ = rand.Read(depot[:])
		depotID := 20000 + int(binary.BigEndian.Uint16(depot[:])%55000)
		var chunk [10]byte
		_, _ = rand.Read(chunk[:])
		return fmt.Sprintf("/depot/%d/chunk/%s", depotID, hex.EncodeToString(chunk[:]))
	default:
		var id [8]byte
		_, _ = rand.Read(id[:])
		return fmt.Sprintf("/appcache/http/%s.bin", hex.EncodeToString(id[:]))
	}
}

func (p *Steamlike) ExtraHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      "Valve/Steam HTTP Client 1.0",
		"Accept":          "*/*",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip,identity,*;q=0",
		"Referer":         "https://store.steampowered.com/",
	}
}
