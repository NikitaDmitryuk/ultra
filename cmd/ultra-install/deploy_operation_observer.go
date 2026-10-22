package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// This identifies an observing SSH client; it never authorizes a mutator.
type deployOperationObserver struct {
	Schema           int    `json:"schema"`
	RequestSHA256    string `json:"request_sha256"`
	PID              int    `json:"pid"`
	Starttime        string `json:"starttime"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArgvSHA256       string `json:"argv_sha256"`
}

func deployObserverStarttime(raw []byte) (string, error) {
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return "", errors.New("deploy_operation_observer_invalid")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("deploy_operation_observer_invalid")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("deploy_operation_observer_invalid")
	}
	return fields[19], nil
}

func publishDeployOperationObserver(directory, identity string) (func(), error) {
	if !runtimeHostValidDigest(identity) {
		return nil, errors.New("deploy_operation_observer_invalid")
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return nil, err
	}
	start, err := deployObserverStarttime(stat)
	if err != nil {
		return nil, err
	}
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	argv, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return nil, err
	}
	observer := deployOperationObserver{1, identity, os.Getpid(), start, digestSHA256(executable), digestSHA256(argv)}
	root := filepath.Join(directory, "observers")
	if err = ensurePrivateBootstrapDirectory(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, fmt.Sprintf("%d-%s.json", observer.PID, start))
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		return nil, errors.New("deploy_operation_observer_exists")
	}
	if err = saveDeployOperation(path, observer); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(observer)
	if err != nil {
		return nil, err
	}
	return func() {
		current, statErr := os.Lstat(path)
		if statErr != nil || !os.SameFile(info, current) {
			return
		}
		data, readErr := readRebuildInput(path, true)
		if readErr == nil && bytes.Equal(data, raw) {
			_ = os.Remove(path)
		}
	}, nil
}
