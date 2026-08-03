//go:build !remote

package abi

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTforkPurgeSocketsAndSignalSuccess(t *testing.T) {
	rootfsList := []string{t.TempDir(), t.TempDir()}
	// Keep the overlapped purge path from reintroducing GNU find and its
	// OverlayFS inode-loop detection.
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "find"), []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)

	const socketRel = "run/test.sock"
	for _, rootfs := range rootfsList {
		socketPath := filepath.Join(rootfs, socketRel)
		if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
			t.Fatal(err)
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(t.TempDir(), "sockets.manifest")
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()

	if err := tforkPurgeSocketsAndSignal(rootfsList, manifestPath, writeEnd); err != nil {
		t.Fatalf("purge and signal failed: %v", err)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatal(err)
	}

	var got [1]byte
	if n, err := readEnd.Read(got[:]); err != nil || n != 1 || got[0] != 1 {
		t.Fatalf("barrier read = (%d, %v, %v); want (1, nil, [1])", n, err, got[:n])
	}
	for _, rootfs := range rootfsList {
		if _, err := os.Lstat(filepath.Join(rootfs, socketRel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket remains in %s: %v", rootfs, err)
		}
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(manifest), socketRel+"\x00"; got != want {
		t.Fatalf("manifest = %q; want %q", got, want)
	}
}

func TestTforkPurgeSocketsAndSignalFailureKeepsBarrierClosed(t *testing.T) {
	missingRootfs := filepath.Join(t.TempDir(), "missing")
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()

	if err := tforkPurgeSocketsAndSignal([]string{missingRootfs}, filepath.Join(t.TempDir(), "sockets.manifest"), writeEnd); err == nil {
		t.Fatal("purge unexpectedly succeeded")
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatal(err)
	}

	var got [1]byte
	if n, err := readEnd.Read(got[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("barrier read = (%d, %v); want (0, EOF)", n, err)
	}
}
