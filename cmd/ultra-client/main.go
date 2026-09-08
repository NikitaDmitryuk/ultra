// Command ultra-client runs an exported ultra profile as loopback SOCKS and HTTP proxies.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func render(data []byte, profile, socks, httpAddr string) ([]byte, error) {
	for _, addr := range []string{socks, httpAddr} {
		host, port, err := net.SplitHostPort(addr)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 1 || n > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return nil, fmt.Errorf("proxy must listen on a loopback IP and nonzero port")
		}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if raw, ok := doc["profiles"]; ok {
		var profiles []struct {
			ID   string `json:"id"`
			Full string `json:"full_xray_config_base64"`
		}
		if err := json.Unmarshal(raw, &profiles); err != nil {
			return nil, err
		}
		found := false
		for _, p := range profiles {
			if p.ID == profile {
				var err error
				data, err = base64.StdEncoding.DecodeString(p.Full)
				if err != nil {
					return nil, err
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("requested profile is not configured")
		}
	} else if raw, ok := doc["full_xray_config_base64"]; ok {
		if profile != "fast_tcp_reality" {
			return nil, fmt.Errorf("legacy export contains only fast_tcp_reality")
		}
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, err
		}
		var err error
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
	}
	var full map[string]any
	if err := json.Unmarshal(data, &full); err != nil {
		return nil, err
	}
	if _, ok := full["outbounds"]; !ok {
		return nil, fmt.Errorf("missing outbounds")
	}
	inbound := func(addr, protocol string) map[string]any {
		host, port, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(port)
		return map[string]any{"listen": host, "port": n, "protocol": protocol, "settings": map[string]any{"auth": "noauth", "udp": protocol == "socks"}}
	}
	full["inbounds"] = []any{inbound(socks, "socks"), inbound(httpAddr, "http")}
	full["log"] = map[string]any{"loglevel": "warning"}
	return json.MarshalIndent(full, "", "  ")
}
func run() error {
	source := flag.String("config", "client.json", "exported /client JSON or full Xray config")
	profile := flag.String("profile", "fast_tcp_reality", "configured profile ID")
	socks := flag.String("socks", "127.0.0.1:10808", "local SOCKS address")
	httpAddr := flag.String("http", "127.0.0.1:10809", "local HTTP proxy address")
	output := flag.String("render", "", "write private config and exit")
	flag.Parse()
	data, err := os.ReadFile(*source)
	if err != nil {
		return err
	}
	data, err = render(data, *profile, *socks, *httpAddr)
	if err != nil {
		return err
	}
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	var r proxy.Runner
	if err := r.StartJSON(data); err != nil {
		return fmt.Errorf("cannot start client; check profile and certificate settings")
	}
	defer func() { _ = r.Close() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
