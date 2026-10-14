package deployansible

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalPreparationInterruptedExportCanRetry(t *testing.T) {
	for _, failure := range []error{syscall.ENOSPC, syscall.EROFS} {
		t.Run(failure.Error(), func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "operation")
			raw := []byte(`{"inventory":{},"variables":{}}`)
			calls := 0
			export := func(path string) error {
				calls++
				if err := os.Mkdir(path, 0700); err != nil {
					return err
				}
				if err := writePrivate(filepath.Join(path, "partial"), []byte("incomplete")); err != nil {
					return err
				}
				// Neither request nor job is visible to a resumed executor yet.
				if _, err := os.Lstat(directory); !os.IsNotExist(err) {
					t.Fatal("published incomplete job")
				}
				return failure
			}
			if err := prepareLocalOperation(directory, "ingress", raw, "identity", export); !errors.Is(err, failure) {
				t.Fatalf("failure: %v", err)
			}
			if _, err := os.Lstat(directory); !os.IsNotExist(err) {
				t.Fatal("failed export left committed job")
			}
			if err := prepareLocalOperation(directory, "ingress", raw, "identity", Export); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(directory, "bundle", "controller.py")); err != nil {
				t.Fatal(err)
			}
			if err := prepareLocalOperation(directory, "ingress", raw, "identity", export); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("replaced frozen bundle on retry")
			}
			if err := prepareLocalOperation(directory, "ingress", []byte("changed"), "identity", export); err == nil {
				t.Fatal("changed request accepted")
			}
		})
	}
}

func TestLocalPreparationIgnoresUnpublishedCrashWorkspace(t *testing.T) {
	root := t.TempDir()
	// An abruptly terminated preparer can leave a private staging directory;
	// its contents are never used as an executable operation on restart.
	staging, err := os.MkdirTemp(root, ".prepare-local-")
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(staging, "job.json"), []byte(`{"schema_version":`)); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "operation")
	if err := prepareLocalOperation(directory, "ingress", []byte(`{}`), "identity", Export); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "bundle", "controller.py")); err != nil {
		t.Fatal(err)
	}
}
