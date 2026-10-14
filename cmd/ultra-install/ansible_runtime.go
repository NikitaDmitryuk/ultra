package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// resolveAnsibleRuntime boots only pinned offline dependencies, not server setup.
func resolveAnsibleRuntime(ctx context.Context, p *installplan.InstallPlan, stateRoot, requested string) (string, error) {
	if requested != "" {
		if !filepath.IsAbs(requested) {
			return "", errors.New("absolute Ansible executable required")
		}
		info, err := os.Stat(requested)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return "", errors.New("ansible executable unavailable")
		}
		return requested, nil
	}
	installed := "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	if info, err := os.Stat(installed); p.Automation == nil && err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
		return installed, nil
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || p.Automation == nil {
		return "", errors.New("offline Ansible requires a complete release on a supported Linux controller")
	}
	manifest, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	if err != nil {
		return "", err
	}
	asset, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		return "", err
	}
	if installedRuntimeMatches(installed, "/opt/ultra-ansible/current/runtime.sha256", asset.SHA) {
		return installed, nil
	}
	return preparePinnedAnsibleRuntime(ctx, stateRoot, filepath.Join(p.Automation.ReleaseDir, asset.Name), asset.SHA)
}

func preparePinnedAnsibleRuntime(ctx context.Context, stateRoot, archive, expectedSHA string) (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || !filepath.IsAbs(archive) || !filepath.IsAbs(stateRoot) || len(expectedSHA) != 64 {
		return "", errors.New("unsupported offline recovery runtime input")
	}
	info, statErr := os.Lstat(archive)
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 160<<20 {
		return "", errors.New("invalid offline runtime archive")
	}
	actual, err := sourceSHA(archive)
	if err != nil || actual != expectedSHA {
		return "", errors.New("offline runtime archive checksum mismatch")
	}
	directory := filepath.Join(stateRoot, "runtime-"+expectedSHA)
	cacheRelease, err := operatorRuntimeLock(directory, true)
	if err != nil {
		return "", err
	}
	defer cacheRelease()
	if err = ensurePrivateBootstrapDirectory(directory); err != nil {
		return "", err
	}
	_, release, err := deployansible.WithOperationLock(ctx, directory)
	if err != nil {
		return "", errors.New("offline runtime preparation already in progress")
	}
	defer release()
	executable := filepath.Join(directory, "venv", "bin", "ansible-playbook")
	marker := filepath.Join(directory, "ready")
	if data, err := os.ReadFile(marker); err == nil && string(data) == expectedSHA {
		info, err := os.Stat(executable)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return executable, nil
		}
		return "", errors.New("committed Ansible runtime is incomplete")
	}
	version := exec.CommandContext(ctx, "/usr/bin/python3", "-c", "import sys;sys.exit(0 if (3,12) <= sys.version_info[:2] <= (3,14) else 1)")
	if version.Run() != nil {
		return "", errors.New("offline Ansible requires Python 3.12 through 3.14")
	}
	if err = extractRuntime(archive, directory); err != nil {
		return "", err
	}
	wheels, err := filepath.Glob(filepath.Join(directory, "wheels", "pip-25.3-*.whl"))
	if err != nil || len(wheels) != 1 {
		return "", errors.New("pinned offline pip wheel missing")
	}
	run := func(program string, args ...string) error {
		command := exec.CommandContext(ctx, program, args...)
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + directory}
		if command.Run() != nil {
			return errors.New("offline Ansible runtime preparation failed")
		}
		return nil
	}
	if err = ensurePrivateBootstrapDirectory(filepath.Join(directory, "venv")); err != nil {
		return "", err
	}
	if err = run("/usr/bin/python3", "-m", "venv", "--without-pip", filepath.Join(directory, "venv")); err != nil {
		return "", err
	}
	python := filepath.Join(directory, "venv", "bin", "python3")
	boot := "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
	if err = run(python, "-c", boot, wheels[0], "--isolated", "--disable-pip-version-check", "install", "--no-index", "--require-hashes", "--find-links="+filepath.Join(directory, "wheels"), "-r", filepath.Join(directory, "requirements.lock")); err != nil {
		return "", err
	}
	if err = run(executable, "--version"); err != nil {
		return "", err
	}
	if err = sealPreparedOperatorRuntime(directory, expectedSHA); err != nil {
		return "", err
	}
	if err = writeUpgradeInput(marker, []byte(expectedSHA)); err != nil {
		return "", err
	}
	return executable, nil
}

func installedRuntimeMatches(executable, marker, sha string) bool {
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return false
	}
	info, err = os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return false
	}
	data, err := os.ReadFile(marker)
	return err == nil && strings.TrimSpace(string(data)) == sha
}

func extractRuntime(source, directory string) error {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer compressed.Close() //nolint:errcheck
	reader := tar.NewReader(compressed)
	var total int64
	count := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			if name != "wheels" && name != "wheels/" {
				return errors.New("unexpected runtime directory")
			}
			continue
		}
		valid := name == "requirements.lock" || (strings.HasPrefix(name, "wheels/") && strings.HasSuffix(name, ".whl") && filepath.Base(name) == strings.TrimPrefix(name, "wheels/"))
		if !valid || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 64<<20 {
			return errors.New("invalid offline runtime member")
		}
		count++
		total += header.Size
		if count > 64 || total > 128<<20 {
			return errors.New("offline runtime exceeds bounds")
		}
		target := filepath.Join(directory, filepath.FromSlash(name))
		if err = ensurePrivateBootstrapDirectory(filepath.Dir(target)); err != nil {
			return err
		}
		if info, e := os.Lstat(target); e == nil && !info.Mode().IsRegular() {
			return errors.New("runtime member is not regular")
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return errors.New("truncated runtime member")
		}
		if err = writeUpgradeInput(target, data); err != nil {
			return fmt.Errorf("immutable runtime conflict: %w", err)
		}
	}
}
