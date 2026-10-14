package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
)

type channelIdentity struct {
	Version        string `json:"version"`
	SourceCommit   string `json:"source_commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type channelState struct {
	Schema   int               `json:"schema_version"`
	Accepted *channelIdentity  `json:"accepted,omitempty"`
	Pending  *channelIdentity  `json:"pending,omitempty"`
	Failed   map[string]string `json:"failed"`
}

// Channel state is retained as recovery metadata because upgrade retry clears
// failed-version blocks written by older installations.
func stableVersion(version string) bool {
	return regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version)
}

func validateChannelIdentity(value *channelIdentity) bool {
	return value == nil || (stableVersion(value.Version) && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(value.SourceCommit) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(value.ManifestSHA256))
}

func readChannelState(path string) (channelState, error) {
	state := channelState{Schema: 1, Failed: map[string]string{}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return state, errors.New("auto_channel_state_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil || state.Schema != 1 || !validateChannelIdentity(state.Accepted) || !validateChannelIdentity(state.Pending) || len(state.Failed) > 128 {
		return state, errors.New("auto_channel_state_invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return state, errors.New("auto_channel_state_invalid")
	}
	for version, code := range state.Failed {
		if !stableVersion(version) || (code != "activation_failed" && code != "resume_failed") {
			return state, errors.New("auto_channel_state_invalid")
		}
	}
	if state.Failed == nil {
		state.Failed = map[string]string{}
	}
	return state, nil
}

// Legacy recovery bundles can contain identity-only channel metadata. Keep
// its strict, read-only validation without reintroducing automatic activation.
func runVerifyChannelState(args []string) {
	fs := flag.NewFlagSet("verify-channel-state", flag.ExitOnError)
	path := fs.String("file", "/var/lib/ultra-ansible/channel/state.json", "private identity-only channel metadata")
	_ = fs.Parse(args)
	_, err := readChannelState(*path)
	exitOnErr("channel metadata validation", err)
}
