// state-proof checks monotonic allowances of a STOPPED disposable relay journal.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
)

func run() error {
	state := flag.String("state", "", "existing stopped drill journal")
	baseline := flag.String("baseline", "", "private baseline file")
	compare := flag.Bool("compare", false, "assert no allowance increased")
	flag.Parse()
	if *state == "" || *baseline == "" {
		return fmt.Errorf("paths required")
	}
	info, err := os.Lstat(*state)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("existing regular journal required")
	}
	store, err := runtimestate.Open(*state)
	if err != nil {
		return fmt.Errorf("journal unavailable")
	}
	defer func() { _ = store.Close() }()
	snapshot, err := store.LoadSnapshot()
	if err != nil {
		return fmt.Errorf("snapshot unavailable")
	}
	var payload struct {
		Limits []runtimestate.QuotaLimit `json:"limits"`
	}
	if err = json.Unmarshal(snapshot.Payload, &payload); err != nil {
		return fmt.Errorf("snapshot incompatible")
	}
	remaining := map[string]int64{}
	for _, limit := range payload.Limits {
		n, e := store.Remaining(limit.AccountID, limit.ExitID)
		if e != nil {
			return fmt.Errorf("allowance unavailable")
		}
		remaining[limit.AccountID+"/"+limit.ExitID] = n
	}
	if *compare {
		info, e := os.Lstat(*baseline)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("private baseline required")
		}
		raw, e := os.ReadFile(*baseline)
		if e != nil {
			return fmt.Errorf("baseline unavailable")
		}
		before := map[string]int64{}
		if json.Unmarshal(raw, &before) != nil || len(before) == 0 || len(before) != len(remaining) {
			return fmt.Errorf("baseline mismatch")
		}
		for key, old := range before {
			now, ok := remaining[key]
			if !ok || now > old {
				return fmt.Errorf("allowance increased")
			}
		}
		fmt.Println("Stopped journal allowances did not increase")
		return nil
	}
	raw, err := json.Marshal(remaining)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*baseline, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("baseline creation failed")
	}
	_, err = f.Write(raw)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("baseline write failed")
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("baseline sync failed")
	}
	return f.Close()
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
