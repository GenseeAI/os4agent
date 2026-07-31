//go:build !remote

package abi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTforkInjectFault(t *testing.T) {
	t.Setenv("PODMAN_TFORK_FAULT_INJECT", "after_freeze, before_commit")
	for _, stage := range []string{"after_freeze", "before_commit"} {
		if err := tforkInjectFault(stage); err == nil {
			t.Fatalf("expected injected fault at %s", stage)
		}
	}
	if err := tforkInjectFault("after_restore"); err != nil {
		t.Fatalf("unexpected fault at unselected stage: %v", err)
	}
}

func TestTforkCgroupFSPath(t *testing.T) {
	for _, unsafe := range []string{"", ".", "/", "..", "../escape"} {
		if got := tforkCgroupFSPath(unsafe); got != "" {
			t.Errorf("tforkCgroupFSPath(%q) = %q; want empty", unsafe, got)
		}
	}
	const rel = "machine.slice/libpod-test"
	if got, want := tforkCgroupFSPath(rel), "/sys/fs/cgroup/"+rel; got != want {
		t.Fatalf("tforkCgroupFSPath(%q) = %q; want %q", rel, got, want)
	}
}

func TestTforkPIDRunning(t *testing.T) {
	if err := tforkPIDRunning(os.Getpid()); err != nil {
		t.Fatalf("current process should be running: %v", err)
	}
	if err := tforkPIDRunning(-1); err == nil {
		t.Fatal("negative pid unexpectedly reported running")
	}
}

func TestTforkTransactionRollbackIsIdempotent(t *testing.T) {
	temp := t.TempDir()
	bundle := filepath.Join(temp, "graph", "tfork-bundles", "batch")
	runtimeBatch := filepath.Join(temp, "run", "tfork", "batch")
	for _, path := range []string{bundle, runtimeBatch} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	restoreCalls := 0
	txn := newTforkCloneTransaction(t.Context(), nil, nil, bundle, 1)
	txn.setRuntimeBatchDir(runtimeBatch)
	txn.setSourceRestore(func() error {
		restoreCalls++
		return nil
	})
	txn.rollback(errors.New("test"))
	txn.rollback(errors.New("test again"))

	if restoreCalls != 1 {
		t.Fatalf("source restore called %d times; want exactly once", restoreCalls)
	}
	for _, path := range []string{bundle, runtimeBatch} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback left %s: %v", path, err)
		}
	}
}
