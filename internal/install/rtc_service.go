package install

import (
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
)

type RTCServiceDeployment struct {
	Enabled          bool   `json:"enabled"`
	ContentFile      string `json:"content_file,omitempty"`
	SupervisorBinary string `json:"supervisor_binary,omitempty"`
	GatewayPort      int    `json:"gateway_port,omitempty"`
}

func (d *RTCServiceDeployment) Validate() error {
	if d == nil || !d.Enabled {
		return nil
	}
	if d.ContentFile == "" || d.SupervisorBinary == "" || d.GatewayPort < 1024 || d.GatewayPort > 65535 {
		return errors.New("rtc: content file, supervisor binary and gateway port are required")
	}
	return nil
}
func (d *RTCServiceDeployment) Spec() rtc.ServiceConfig {
	if d == nil || !d.Enabled {
		return rtc.ServiceConfig{}
	}
	return rtc.ServiceConfig{Enabled: true, ContentFile: "/etc/ultra-rtc/content.json", EncryptionKeyFile: "/etc/ultra-rtc/keys.json", Socket: "/run/ultra-rtc/control.sock", GatewayPort: d.GatewayPort}
}

// RTCServiceUnit uses a separate user and only a private runtime directory.
func RTCServiceUnit(port, relayUID int) string {
	return fmt.Sprintf(`[Unit]
Description=Ultra RTC supervisor
After=network-online.target
Wants=network-online.target
[Service]
User=ultra-rtc
Group=ultra-relay
ExecStart=/usr/local/bin/ultra-rtc-supervisor -content /etc/ultra-rtc/content.json -relay-uid %d -gateway-port %d
RuntimeDirectory=ultra-rtc
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=20
MemoryMax=2G
CPUQuota=200%%
TasksMax=2048
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
UMask=0077
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
`, relayUID, port)
}
