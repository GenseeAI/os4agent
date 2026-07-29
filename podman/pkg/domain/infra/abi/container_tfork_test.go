//go:build !remote && linux

package abi

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTforkPurgeSockets(t *testing.T) {
	rootfs := t.TempDir()
	socketDir := filepath.Join(rootfs, "run", "nested")
	require.NoError(t, os.MkdirAll(socketDir, 0o755))

	socketPath := filepath.Join(socketDir, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	require.NoError(t, err)
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
	})

	regularPath := filepath.Join(socketDir, "keep")
	require.NoError(t, os.WriteFile(regularPath, []byte("keep"), 0o644))

	outside := t.TempDir()
	outsidePath := filepath.Join(outside, "outside")
	require.NoError(t, os.WriteFile(outsidePath, []byte("outside"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(rootfs, "outside-link")))

	require.NoError(t, tforkPurgeSockets(rootfs))
	require.NoFileExists(t, socketPath)
	require.FileExists(t, regularPath)
	require.FileExists(t, outsidePath)
}
