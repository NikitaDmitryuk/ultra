package deployansible

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (c Client) waitJob(ctx context.Context, message Message) error {
	response, err := c.exchange(ctx, message)
	for err == nil {
		switch response.State {
		case "succeeded":
			return nil
		case "failed":
			return errors.New("ansible replica operation failed")
		case "queued", "running":
		default:
			return errors.New("invalid replica operation state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		response, err = c.exchange(ctx, Message{Action: "status", ID: message.ID})
	}
	return err
}

func (c Client) ConfigureReplica(ctx context.Context, request ReplicaRequest) error {
	if err := request.ValidatePolicy(); err != nil {
		return err
	}
	attempt, err := newReplicaAttempt()
	if err != nil {
		return err
	}
	return c.waitJob(ctx, Message{Action: "submit-replica", ID: attempt, Replica: &request})
}

func (c Client) StopReplicaTunnel(ctx context.Context, id string) error {
	if !jobID.MatchString(id) {
		return errors.New("invalid replica identity")
	}
	attempt, err := newReplicaAttempt()
	if err != nil {
		return err
	}
	return c.waitJob(ctx, Message{Action: "stop-replica", ID: attempt, NodeID: id})
}

func newReplicaAttempt() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:]), nil
}

func openReplicaInputs(request ReplicaRequest) ([]*os.File, error) {
	if err := request.ValidatePolicy(); err != nil {
		return nil, err
	}
	var files []*os.File
	for _, path := range []string{request.Identity, request.KnownHosts} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			closeInputs(files)
			return nil, errors.New("regular replica source required")
		}
		file, err := os.Open(path)
		if err != nil {
			closeInputs(files)
			return nil, errors.New("replica source unavailable")
		}
		files = append(files, file)
	}
	return files, nil
}

func prepareReplica(directory, operation string, request any, inputs []*os.File) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	job := map[string]any{"schema_version": 1, "operation": operation, "request_sha256": hash, "binary_sha256": hash}
	sources := map[string][]byte{}
	if operation == "configure-replica" {
		if len(inputs) != 2 {
			return errors.New("two replica sources required")
		}
		for index, name := range []string{"identity", "known_hosts"} {
			limit := int64(1 << 20)
			if index == 0 {
				limit = 65536
			}
			data, err := readInput(inputs[index], limit, index == 0)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			job[name+"_sha256"] = hex.EncodeToString(digest[:])
			sources[name] = data
		}
	}
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
			return errors.New("private replica job required")
		}
		old, err := os.ReadFile(filepath.Join(directory, "job.json"))
		var previous map[string]any
		if err == nil && json.Unmarshal(old, &previous) == nil {
			current, _ := json.Marshal(job)
			past, _ := json.Marshal(previous)
			if string(current) != string(past) {
				return errors.New("replica operation conflict")
			}
		} else if !os.IsNotExist(err) {
			return errors.New("replica job unavailable")
		}
		if _, err := os.Stat(filepath.Join(directory, "prepared")); err == nil {
			return nil
		}
		if err := os.RemoveAll(directory); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	lock, err := controllerLock(filepath.Join(directory, "execution.lock"))
	if err != nil {
		return err
	}
	defer lock.Close() //nolint:errcheck
	if err := writePrivate(filepath.Join(directory, "request.json"), raw); err != nil {
		return err
	}
	for name, data := range sources {
		if err := writePrivate(filepath.Join(directory, name), data); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
		return err
	}
	if err := Export(filepath.Join(directory, "bundle")); err != nil {
		return err
	}
	if err := WriteRetentionReceipt(filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle.retention.json"), map[string]string{"request_sha256": hash}); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(directory, "prepared"), []byte("1\n")); err != nil {
		return err
	}
	if err := syncTree(directory); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(directory))
}
