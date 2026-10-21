package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const installedRuntimeSecrets = "installed-runtime"

func planSecretsSource(p *installplan.InstallPlan) string {
	if p.SecretSource == "" {
		return "canonical"
	}
	return p.SecretSource
}

func selectPlanSecrets(p *installplan.InstallPlan, source string) error {
	if source == "canonical" {
		if p != nil {
			p.SecretSource, p.SecretResolver = "", nil
		}
		return nil
	}
	if source != installedRuntimeSecrets {
		return errors.New("secrets_source_invalid")
	}
	if p == nil || os.Geteuid() != 0 {
		return errors.New("installed_runtime_secrets_bridge_required")
	}
	if err := validateInstalledRuntimeSource(p, os.Geteuid(), !p.BridgeNative && attestLocalLifecycleBridge(p)); err != nil {
		return err
	}
	relay, err := user.Lookup("ultra-relay")
	if err != nil {
		return errors.New("installed_runtime_secrets_identity_unavailable")
	}
	uid, uidErr := strconv.ParseUint(relay.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(relay.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 {
		return errors.New("installed_runtime_secrets_identity_unavailable")
	}
	p.SecretSource = source
	p.SecretResolver = installedRuntimeResolver(p.Bot.Enabled, p.Automation != nil, func(path string) ([]byte, error) {
		return readInstalledRuntimeFile("/", path, 0, 0, uint32(uid), uint32(gid))
	})
	return nil
}

func validateInstalledRuntimeSource(p *installplan.InstallPlan, euid int, confirmedBridge bool) error {
	if euid != 0 || p == nil || p.BridgeNative || !confirmedBridge {
		return errors.New("installed_runtime_secrets_bridge_required")
	}
	if p.Automation != nil && p.Automation.DNS != nil && p.Automation.DNS.Provider != "vultr" {
		return errors.New("installed_runtime_secrets_provider_unsupported")
	}
	return nil
}

// Only these two fixed inputs are supported. No environment or legacy path fallback.
func installedRuntimeResolver(bot, provider bool, read func(string) ([]byte, error)) func() (map[string]string, error) {
	resolve := func() (map[string]string, error) {
		values := map[string]string{}
		if bot {
			raw, err := read("/etc/ultra-relay/bot.env")
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(string(raw), "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
				if !ok || key != "TELEGRAM_BOT_TOKEN" {
					continue
				}
				if _, exists := values[key]; exists {
					return nil, errors.New("installed_runtime_secrets_bot_invalid")
				}
				// BotEnvironment writes systemd double-quoted values with only these escapes.
				value = strings.TrimSpace(value)
				if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
					value = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(value[1 : len(value)-1])
				}
				if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n\x00\"\\") {
					return nil, errors.New("installed_runtime_secrets_bot_invalid")
				}
				values[key] = value
			}
			if values["TELEGRAM_BOT_TOKEN"] == "" {
				return nil, errors.New("installed_runtime_secrets_bot_missing")
			}
		}
		if provider {
			raw, err := read("/var/lib/ultra-relay/automation/vultr-api-key")
			if err != nil {
				return nil, err
			}
			key := strings.TrimSpace(string(raw))
			if key == "" || strings.ContainsAny(key, "\r\n\x00") {
				return nil, errors.New("installed_runtime_secrets_provider_invalid")
			}
			values["ULTRA_VULTR_API_KEY"] = key
		}
		return values, nil
	}
	var mutex sync.Mutex
	var initial *[32]byte
	return func() (map[string]string, error) {
		mutex.Lock()
		defer mutex.Unlock()
		values, err := resolve()
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(values)
		sum := sha256.Sum256(raw)
		if initial != nil && sum != *initial {
			return nil, errors.New("installed_runtime_secrets_changed")
		}
		if initial == nil {
			initial = &sum
		}
		return values, nil
	}
}

// Descriptor-relative traversal prevents ancestor replacement from redirecting a read.
// root and owner arguments are internal test seams; production always uses / and root.
func readInstalledRuntimeFile(root, path string, rootUID, rootGID, relayUID, relayGID uint32) ([]byte, error) {
	return readInstalledRuntimeFileChecked(root, path, rootUID, rootGID, relayUID, relayGID, nil)
}

func readInstalledRuntimeFileChecked(root, path string, rootUID, rootGID, relayUID, relayGID uint32, afterRead func()) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, errors.New("installed_runtime_secrets_untrusted") }
	if path != "/etc/ultra-relay/bot.env" && path != "/var/lib/ultra-relay/automation/vultr-api-key" {
		return fail()
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	files := []*os.File{os.NewFile(uintptr(fd), root)}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	type snapshot struct {
		file   *os.File
		stat   syscall.Stat_t
		parent *os.File
		name   string
	}
	snapshots := []snapshot{}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := ""
	for index := -1; index < len(components); index++ {
		file := files[len(files)-1]
		var parent *os.File
		name := ""
		if index >= 0 {
			parent = file
			name = components[index]
			current += "/" + name
			flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
			if index < len(components)-1 {
				flags |= syscall.O_DIRECTORY
			}
			child, openErr := syscall.Openat(int(parent.Fd()), name, flags, 0)
			if openErr != nil {
				return fail()
			}
			file = os.NewFile(uintptr(child), current)
			files = append(files, file)
		}
		var stat syscall.Stat_t
		if syscall.Fstat(int(file.Fd()), &stat) != nil {
			return fail()
		}
		uid, gid := rootUID, rootGID
		if current == "/etc/ultra-relay" || current == "/var/lib/ultra-relay" ||
			strings.HasPrefix(current, "/var/lib/ultra-relay/automation") {
			uid, gid = relayUID, relayGID
		}
		if stat.Uid != uid || stat.Gid != gid || stat.Mode&0022 != 0 {
			return fail()
		}
		last := index == len(components)-1
		if last {
			if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size < 1 ||
				stat.Size > 65536 {
				return fail()
			}
		} else if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return fail()
		}
		if current == "/var/lib/ultra-relay" {
			if mode := stat.Mode & 07777; mode != 0700 && mode != 0755 {
				return fail()
			}
		} else if (current == "/etc/ultra-relay" || current == "/var/lib/ultra-relay/automation") && stat.Mode&07777 != 0700 {
			return fail()
		}
		snapshots = append(snapshots, snapshot{file, stat, parent, name})
	}
	raw, err := io.ReadAll(io.LimitReader(files[len(files)-1], 65537))
	if err != nil || len(raw) > 65536 || int64(len(raw)) != snapshots[len(snapshots)-1].stat.Size {
		return fail()
	}
	if afterRead != nil {
		afterRead()
	}
	for _, saved := range snapshots {
		var after syscall.Stat_t
		if syscall.Fstat(int(saved.file.Fd()), &after) != nil || !stableRuntimeSecretStat(saved.stat, after) {
			return fail()
		}
		if saved.parent != nil {
			// Reopen by the original parent descriptor to reject replacement/unlink.
			check, openErr := syscall.Openat(
				int(saved.parent.Fd()),
				saved.name,
				syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
				0,
			)
			if openErr != nil {
				return fail()
			}
			statErr := syscall.Fstat(check, &after)
			_ = syscall.Close(check)
			if statErr != nil || !stableRuntimeSecretStat(saved.stat, after) {
				return fail()
			}
		}
	}
	return raw, nil
}

func stableRuntimeSecretStat(before, after syscall.Stat_t) bool {
	// Reading can update atime. Content/identity/ownership/mode changes must fail.
	before.Atim, after.Atim = syscall.Timespec{}, syscall.Timespec{}
	return before == after
}

func validSecretsSource(source string) bool {
	return source == "" || source == "canonical" || source == installedRuntimeSecrets
}

type journalSecretsSource string

func (source *journalSecretsSource) UnmarshalJSON(raw []byte) error {
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" || !validSecretsSource(value) {
		return errors.New("secrets_source_invalid")
	}
	*source = journalSecretsSource(value)
	return nil
}

// Verification restores only a nonsecret selector from already authenticated
// journal evidence. It never authorizes secret reads or installs a resolver.
func bindVerificationSecretsSource(p *installplan.InstallPlan, source string) error {
	if p == nil || !validSecretsSource(source) {
		return errors.New("secrets_source_invalid")
	}
	p.SecretSource = source
	return nil
}
