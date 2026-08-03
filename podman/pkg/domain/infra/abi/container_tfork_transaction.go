//go:build !remote

package abi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containers/podman/v5/libpod"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const tforkRollbackWait = 3 * time.Second

type tforkTrackedPID struct {
	pid       int
	startTime uint64
	role      string
}

// tforkCloneTransaction owns every host-side object created before a clone is
// published.  Ownership is transferred to libpod only by commit.  Until then,
// every return path converges on rollback.
type tforkCloneTransaction struct {
	ctx context.Context
	rt  *libpod.Runtime
	src *libpod.Container

	bundleDir       string
	runtimeBatchDir string
	imgDir          string
	copies          int
	cloneIDs        []string
	cgroupPaths     []string

	restoreSource  func() error
	sourceRestored bool
	registered     []*libpod.Container
	pids           []tforkTrackedPID
	committed      bool
	rolledBack     bool
}

func newTforkCloneTransaction(ctx context.Context, rt *libpod.Runtime, src *libpod.Container, bundleDir string, copies int) *tforkCloneTransaction {
	return &tforkCloneTransaction{
		ctx:       ctx,
		rt:        rt,
		src:       src,
		bundleDir: bundleDir,
		copies:    copies,
	}
}

func (t *tforkCloneTransaction) setCloneIDs(ids []string) {
	t.cloneIDs = append([]string(nil), ids...)
}

func (t *tforkCloneTransaction) setCgroupPaths(paths []string) {
	t.cgroupPaths = append([]string(nil), paths...)
}

func (t *tforkCloneTransaction) setRuntimeBatchDir(path string) {
	t.runtimeBatchDir = path
}

func (t *tforkCloneTransaction) setImageDir(path string) {
	t.imgDir = path
}

func (t *tforkCloneTransaction) setSourceRestore(restore func() error) {
	t.restoreSource = restore
}

func (t *tforkCloneTransaction) restoreSourceOnce() error {
	if t.sourceRestored || t.restoreSource == nil {
		return nil
	}
	if err := t.restoreSource(); err != nil {
		return err
	}
	t.sourceRestored = true
	return nil
}

func (t *tforkCloneTransaction) trackPID(pid int, role string) {
	if pid <= 0 {
		return
	}
	for _, tracked := range t.pids {
		if tracked.pid == pid {
			return
		}
	}
	startTime, err := libpod.ReadProcStartTime(pid)
	if err != nil {
		logrus.Debugf("tfork: transaction cannot record %s pid=%d start time: %v", role, pid, err)
		return
	}
	t.pids = append(t.pids, tforkTrackedPID{pid: pid, startTime: startTime, role: role})
}

func (t *tforkCloneTransaction) addRegistered(ctr *libpod.Container) {
	if ctr != nil {
		t.registered = append(t.registered, ctr)
	}
}

func (t *tforkCloneTransaction) commit() {
	t.committed = true
}

func (t *tforkCloneTransaction) rollback(cause error) {
	if t == nil || t.committed || t.rolledBack {
		return
	}
	t.rolledBack = true
	logrus.Warnf("tfork: rolling back unpublished clone transaction: %v", cause)

	// A registered external clone knows how to tear down its network, state,
	// cgroup, and per-copy storage.  Remove in reverse publication order.
	zero := uint(0)
	for i := len(t.registered) - 1; i >= 0; i-- {
		ctr := t.registered[i]
		if err := t.rt.RemoveContainer(context.WithoutCancel(t.ctx), ctr, true, false, &zero); err != nil {
			logrus.Warnf("tfork: rollback remove registered clone %s: %v", ctr.ID(), err)
		}
	}

	t.trackRestorePIDs()
	t.killCloneCgroups()
	for i := len(t.pids) - 1; i >= 0; i-- {
		t.killTrackedPID(t.pids[i])
	}

	if err := t.restoreSourceOnce(); err != nil {
		logrus.Warnf("tfork: rollback restore source cgroup: %v", err)
	}

	t.removeCloneCgroups()
	for _, id := range t.cloneIDs {
		_ = os.Remove(filepath.Join("/run/libpod/exits", id))
		_ = os.RemoveAll(filepath.Join("/run/crun", id))
	}
	if t.runtimeBatchDir != "" {
		if err := os.RemoveAll(t.runtimeBatchDir); err != nil {
			logrus.Warnf("tfork: rollback remove runtime publication %s: %v", t.runtimeBatchDir, err)
		}
		tforkRemoveEmptyParent(filepath.Dir(t.runtimeBatchDir))
	}
	if t.bundleDir != "" {
		tforkBestEffortBundleReap(t.bundleDir, t.copies)
	}
}

func (t *tforkCloneTransaction) trackRestorePIDs() {
	if t.imgDir == "" {
		return
	}
	for i := 0; i < t.copies; i++ {
		for _, path := range []string{
			filepath.Join(t.imgDir, "tfork.pid"),
			filepath.Join(t.imgDir, fmt.Sprintf("tfork.pid.copy%d", i)),
		} {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			pid, err := parsePIDBytes(data, path)
			if err == nil {
				t.trackPID(pid, "restore-child")
				if child, err := readFirstChildPID(pid); err == nil {
					t.trackPID(child, "clone-init")
				}
			}
		}
	}
}

func (t *tforkCloneTransaction) killCloneCgroups() {
	for _, rel := range t.cgroupPaths {
		root := tforkCgroupFSPath(rel)
		if root == "" {
			continue
		}
		killPath := filepath.Join(root, "cgroup.kill")
		if err := os.WriteFile(killPath, []byte("1"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			logrus.Debugf("tfork: rollback write %s: %v", killPath, err)
		}
	}
}

func (t *tforkCloneTransaction) removeCloneCgroups() {
	deadline := time.Now().Add(tforkRollbackWait)
	for _, rel := range t.cgroupPaths {
		root := tforkCgroupFSPath(rel)
		if root == "" {
			continue
		}
		for {
			err := os.Remove(root)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			if time.Now().After(deadline) {
				logrus.Warnf("tfork: rollback cgroup remains at %s: %v", root, err)
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func tforkCgroupFSPath(rel string) string {
	clean := strings.TrimPrefix(filepath.Clean(rel), string(os.PathSeparator))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return ""
	}
	return filepath.Join("/sys/fs/cgroup", clean)
}

func (t *tforkCloneTransaction) killTrackedPID(tracked tforkTrackedPID) {
	current, err := libpod.ReadProcStartTime(tracked.pid)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return
	}
	if err != nil {
		logrus.Warnf("tfork: rollback cannot verify %s pid=%d: %v; refusing unsafe kill", tracked.role, tracked.pid, err)
		return
	}
	if current != tracked.startTime {
		logrus.Warnf("tfork: rollback %s pid=%d was recycled; refusing kill", tracked.role, tracked.pid)
		return
	}
	descendants := tforkCollectDescendants(tracked.pid)
	for i := len(descendants) - 1; i >= 0; i-- {
		_ = syscall.Kill(descendants[i], syscall.SIGKILL)
	}
	_ = syscall.Kill(tracked.pid, syscall.SIGKILL)
}

func tforkRemoveEmptyParent(path string) {
	if path == "" {
		return
	}
	entries, err := os.ReadDir(path)
	if err == nil && len(entries) == 0 {
		_ = os.Remove(path)
	}
}

func tforkPIDRunning(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return err
	}
	rp := strings.LastIndexByte(string(data), ')')
	if rp < 0 || rp+2 >= len(data) {
		return fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	if data[rp+2] == 'Z' {
		return fmt.Errorf("pid %d is a zombie", pid)
	}
	return nil
}

func tforkInjectFault(stage string) error {
	// PODMAN_TFORK_FAULT_INJECT is an opt-in integration-test hook. Keeping
	// the hook at transaction boundaries exercises the real rollback path;
	// production calls take the unset fast path below without changing state.
	want := strings.TrimSpace(os.Getenv("PODMAN_TFORK_FAULT_INJECT"))
	if want == "" {
		return nil
	}
	for _, candidate := range strings.Split(want, ",") {
		if strings.TrimSpace(candidate) == stage {
			return fmt.Errorf("injected tfork fault at %s", stage)
		}
	}
	return nil
}
