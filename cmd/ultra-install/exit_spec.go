package main

import (
	"encoding/json"
	"path"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func buildExitSpecJSON(
	remoteDir string,
	tun int,
	tunnelUUID string,
	stratName string,
	mimicHost string,
	splitPath string,
	splitTLS config.SplitHTTPTLSSpec,
	tlsProv config.TunnelTLSProvision,
	transport config.TunnelTransport,
	exitAnti *config.AntiCensorSpec,
) ([]byte, error) {
	exitSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleExit,
		MimicPreset:        stratName,
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		ListenAddress:      "0.0.0.0",
		VLESSPort:          tun,
		Exit: config.ExitTunnelSpec{
			TunnelUUID: tunnelUUID,
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS:  splitTLS,
		ExitCertPaths: config.CertPaths{
			CertFile: path.Join(remoteDir, "fullchain.pem"),
			KeyFile:  path.Join(remoteDir, "privkey.pem"),
		},
		AntiCensor: exitAnti,
	}
	if transport != "" {
		exitSpec.TunnelTransport = transport
	}
	if err := exitSpec.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(exitSpec, "", "  ")
}
