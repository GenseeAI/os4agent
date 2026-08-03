package abi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/containers/podman/v5/libpod"
	"github.com/containers/podman/v5/libpod/define"
	"github.com/cyphar/filepath-securejoin/pathrs-lite"

	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/containers/podman/v5/utils"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"go.podman.io/common/libnetwork/types"
	commonconfig "go.podman.io/common/pkg/config"
	"go.podman.io/storage/pkg/stringid"
	"golang.org/x/sys/unix"
)

const (
	tforkSourceFreezeTimeout = 10 * time.Second
	tforkSourceThawTimeout   = 10 * time.Second
	tforkCloneReadyTimeout   = 60 * time.Second
	tforkCgroupPollInterval  = 50 * time.Millisecond
	tforkClonePollInterval   = 200 * time.Millisecond
)

type tforkSourceSyncMode string

const (
	tforkSourceSyncFS     tforkSourceSyncMode = "syncfs"
	tforkSourceSyncGlobal tforkSourceSyncMode = "global"
	tforkSourceSyncNone   tforkSourceSyncMode = "none"
)

func tforkSourceSyncModeFromEnv() (tforkSourceSyncMode, error) {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("PODMAN_TFORK_SYNC_MODE")))
	if value == "" {
		return tforkSourceSyncFS, nil
	}
	mode := tforkSourceSyncMode(value)
	switch mode {
	case tforkSourceSyncFS, tforkSourceSyncGlobal, tforkSourceSyncNone:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid PODMAN_TFORK_SYNC_MODE=%q (must be syncfs, global, or none)", value)
	}
}

func tforkSyncSource(rootfs string) error {
	mode, err := tforkSourceSyncModeFromEnv()
	if err != nil {
		return err
	}

	switch mode {
	case tforkSourceSyncNone:
		logrus.Infof("tfork: source sync disabled by PODMAN_TFORK_SYNC_MODE=none")
		return nil
	case tforkSourceSyncGlobal:
		if out, err := exec.Command("sync").CombinedOutput(); err != nil {
			return fmt.Errorf("global sync: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	case tforkSourceSyncFS:
		root, err := os.Open(rootfs)
		if err != nil {
			return fmt.Errorf("open source rootfs %s for syncfs: %w", rootfs, err)
		}
		defer root.Close()
		if err := unix.Syncfs(int(root.Fd())); err != nil {
			return fmt.Errorf("syncfs source rootfs %s: %w", rootfs, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported source sync mode %q", mode)
	}
}

func tforkCloneReadyTimeoutFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("PODMAN_TFORK_CLONE_READY_TIMEOUT_SECS"))
	if value == "" {
		return tforkCloneReadyTimeout
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		logrus.Warnf("tfork: ignoring invalid PODMAN_TFORK_CLONE_READY_TIMEOUT_SECS=%q", value)
		return tforkCloneReadyTimeout
	}
	return time.Duration(seconds) * time.Second
}

func (ic *ContainerEngine) containerCloneLive(ctx context.Context, opts entities.ContainerCloneOptions) (rep *entities.ContainerCreateReport, retErr error) {
	src, err := ic.Libpod.LookupContainer(opts.ID)
	if err != nil {
		return nil, fmt.Errorf("source container %q: %w", opts.ID, err)
	}

	state, err := src.State()
	if err != nil {
		return nil, err
	}
	if state != define.ContainerStateRunning {
		return nil, fmt.Errorf("source %q is not running (state=%s); tfork requires a live source", src.ID(), state.String())
	}
	if manager := src.CgroupManager(); manager != commonconfig.CgroupfsCgroupsManager {
		return nil, fmt.Errorf("tfork currently requires the cgroupfs cgroup manager (source uses %q); retry Podman with --cgroup-manager=cgroupfs", manager)
	}

	copies := opts.Copies
	if copies <= 0 {
		copies = 1
	}
	requestedCopies := copies
	fileInjections, err := tforkParseFileInjections(opts.TforkInjectFiles, requestedCopies)
	if err != nil {
		return nil, err
	}
	useSingleCopyConmon := requestedCopies == 1 && os.Getenv("PODMAN_TFORK_SINGLE_COPY_CONMON") == "1"
	// PODMAN_TFORK_SINGLE_COPY_DIRECT is a debugging escape hatch that skips
	// the n-copy restore helper for single-copy experiments. Production paths
	// keep the n-copy helper even for copies=1 so attach/status handling is
	// consistent with multi-copy forks.
	useSingleCopyDirect := requestedCopies == 1 && os.Getenv("PODMAN_TFORK_SINGLE_COPY_DIRECT") == "1"
	useNcopyRestore := copies > 1 || (requestedCopies == 1 && !useSingleCopyConmon && !useSingleCopyDirect)

	var srcRootfs string
	if cfg := src.Config(); cfg != nil && cfg.ExternalSetup && cfg.Rootfs != "" {
		srcRootfs = cfg.Rootfs
	} else {
		var err error
		srcRootfs, err = src.Mount()
		if err != nil {
			return nil, fmt.Errorf("get source rootfs mount: %w", err)
		}
	}

	bundleParent := filepath.Join(ic.Libpod.StorageConfig().GraphRoot, "tfork-bundles")
	if err := os.MkdirAll(bundleParent, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir tfork-bundles: %w", err)
	}
	batchID := stringid.GenerateRandomID()
	bundleDir := filepath.Join(bundleParent, batchID)
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir bundle: %w", err)
	}
	txn := newTforkCloneTransaction(ctx, ic.Libpod, src, bundleDir, copies)
	defer func() {
		if retErr != nil {
			txn.rollback(retErr)
		}
	}()

	snapRO := filepath.Join(bundleDir, "snap-ro")

	if err := tforkInjectFault("before_freeze"); err != nil {
		return nil, err
	}
	thawSource, err := tforkFreezeSourceCgroup(src, tforkSourceFreezeTimeout)
	if err != nil {
		return nil, fmt.Errorf("freeze source cgroup before tfork snapshot: %w", err)
	}
	txn.setSourceRestore(thawSource)
	if err := tforkInjectFault("after_freeze"); err != nil {
		return nil, err
	}

	if err := tforkSyncSource(srcRootfs); err != nil {
		return nil, err
	}

	recursive := false
	parentUpperFrozen := ""
	if cfg := src.Config(); cfg != nil && cfg.ExternalSetup && opts.TforkOverlayBtrfs {
		parentLower, parentUpper, err := tforkResolveOverlayLayers(srcRootfs)
		if err != nil {
			return nil, fmt.Errorf("resolve parent overlay layers (src is tfork-clone): %w", err)
		}
		recursive = true
		realLower, rerr := filepath.EvalSymlinks(parentLower)
		if rerr != nil {
			return nil, fmt.Errorf("resolve parent snap-ro %s: %w", parentLower, rerr)
		}
		if err := os.Symlink(realLower, snapRO); err != nil {
			return nil, fmt.Errorf("symlink snap-ro -> %s: %w", realLower, err)
		}
		parentUpperFrozen = filepath.Join(bundleDir, "parent-upper-frozen")
		if err := os.MkdirAll(parentUpperFrozen, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir parent-upper-frozen %s: %w", parentUpperFrozen, err)
		}
		if out, err := exec.Command("cp", "-a", "--reflink=always",
			parentUpper+"/.", parentUpperFrozen+"/").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("freeze parent upper (cp --reflink %s -> %s): %s: %w",
				parentUpper, parentUpperFrozen, out, err)
		}
		logrus.Infof("tfork: recursive clone — sharing snap-ro=%s, parent upper reflink-frozen at %s",
			parentLower, parentUpperFrozen)
	} else if opts.TforkOverlayBtrfs {
		if out, err := exec.Command("btrfs", "subvolume", "snapshot", "-r", srcRootfs, snapRO).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("btrfs snapshot src→snap-ro (%s → %s): %s: %w", srcRootfs, snapRO, out, err)
		}
	} else {
		if out, err := exec.Command("btrfs", "subvolume", "snapshot", srcRootfs, snapRO).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("btrfs snapshot src→anchor (%s → %s): %s: %w", srcRootfs, snapRO, out, err)
		}
		if out, err := exec.Command("btrfs", "property", "set", "-ts", snapRO, "ro", "true").CombinedOutput(); err != nil {
			logrus.Warnf("tfork: set ro=true on anchor %s: %s: %v (anchor still functional, just RW)",
				snapRO, strings.TrimSpace(string(out)), err)
		}
	}

	cloneIDs := make([]string, copies)
	cloneRootfsList := make([]string, copies)
	cloneRootfsRel := make([]string, copies)
	overlapSocketPurge := os.Getenv("PODMAN_TFORK_OVERLAP_SOCKET_PURGE") == "1"
	for i := 0; i < copies; i++ {
		cloneIDs[i] = stringid.GenerateRandomID()
		var rel string
		if copies == 1 {
			rel = "rootfs"
		} else {
			rel = fmt.Sprintf("rootfs-%d", i)
		}
		cloneRootfsRel[i] = rel
		cloneRootfsList[i] = filepath.Join(bundleDir, rel)
		if recursive {
			if err := tforkSetupOverlayRootfsFromParent(snapRO, parentUpperFrozen, bundleDir, i, copies, cloneRootfsList[i]); err != nil {
				return nil, fmt.Errorf("setup overlay rootfs for copy %d (recursive): %w", i, err)
			}
		} else if opts.TforkOverlayBtrfs {
			if err := tforkSetupOverlayRootfs(snapRO, bundleDir, i, copies, cloneRootfsList[i]); err != nil {
				return nil, fmt.Errorf("setup overlay rootfs for copy %d: %w", i, err)
			}
		} else {
			if err := tforkSetupSnapSubvolRootfs(srcRootfs, bundleDir, i, copies, cloneRootfsList[i]); err != nil {
				return nil, fmt.Errorf("setup snap-subvol rootfs for copy %d: %w", i, err)
			}
		}
		if !overlapSocketPurge {
			if err := tforkPurgeSockets(cloneRootfsList[i]); err != nil {
				logrus.Warnf("tfork: purge sockets in %s: %v (proceeding)", cloneRootfsList[i], err)
			}
		}

		if srcPID, perr := src.PID(); perr == nil && srcPID > 0 {
			srcResolv := fmt.Sprintf("/proc/%d/root/etc/resolv.conf", srcPID)
			if data, rerr := os.ReadFile(srcResolv); rerr == nil && len(data) > 0 {
				cloneResolv := filepath.Join(cloneRootfsList[i], "etc", "resolv.conf")
				if err := os.MkdirAll(filepath.Dir(cloneResolv), 0o755); err != nil {
					logrus.Warnf("tfork: clone %d mkdir etc: %v", i, err)
				} else if err := os.WriteFile(cloneResolv, data, 0o644); err != nil {
					logrus.Warnf("tfork: clone %d write resolv.conf: %v", i, err)
				}
			} else if rerr != nil {
				logrus.Warnf("tfork: read source resolv.conf %s: %v", srcResolv, rerr)
			}
		}
	}
	var socketPurgeRead *os.File
	var socketPurgeFinished chan struct{}
	var socketPurgeErr error
	waitSocketPurge := func() error {
		if socketPurgeFinished == nil {
			return nil
		}
		<-socketPurgeFinished
		return socketPurgeErr
	}
	if overlapSocketPurge {
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("create socket-purge barrier: %w", err)
		}
		socketPurgeRead = readEnd
		socketPurgeFinished = make(chan struct{})
		manifestPath := filepath.Join(bundleDir, "socket-paths.manifest0")
		go func() {
			defer close(socketPurgeFinished)
			defer writeEnd.Close()
			socketPurgeErr = tforkPurgeSocketsAndSignal(cloneRootfsList, manifestPath, writeEnd)
			if socketPurgeErr != nil {
				logrus.Errorf("tfork: overlapped socket purge failed; restore remains blocked: %v", socketPurgeErr)
			}
		}()
		defer func() {
			_ = waitSocketPurge()
			if socketPurgeRead != nil {
				_ = socketPurgeRead.Close()
			}
		}()
	}
	txn.setCloneIDs(cloneIDs)
	if err := tforkInjectFault("after_filesystem"); err != nil {
		return nil, err
	}

	if recursive && parentUpperFrozen != "" {
		if err := os.RemoveAll(parentUpperFrozen); err != nil {
			if out, derr := exec.Command("btrfs", "subvolume", "delete",
				parentUpperFrozen).CombinedOutput(); derr != nil {
				logrus.Warnf("tfork: delete parent-upper-frozen %s: rm %v; btrfs %s: %v",
					parentUpperFrozen, err, strings.TrimSpace(string(out)), derr)
			}
		}
	}

	if opts.SharedUsr {
		srcPIDForBind, _ := src.PID()
		if err := tforkPrepareSharedUsr(srcPIDForBind); err != nil {
			return nil, fmt.Errorf("shared-/usr: prepare source mountns: %w", err)
		}
	}

	srcSpec := src.Spec()
	if srcSpec == nil {
		return nil, fmt.Errorf("source %q: could not read OCI spec", src.ID())
	}
	cloneSpecs := make([]*spec.Spec, copies)
	cloneNames := make([]string, copies)
	perCopyVolMounts := make([][]tforkVolMount, copies)
	for i, cloneID := range cloneIDs {
		jb, err := json.Marshal(srcSpec)
		if err != nil {
			return nil, fmt.Errorf("marshal source spec: %w", err)
		}
		copySpec := &spec.Spec{}
		if err := json.Unmarshal(jb, copySpec); err != nil {
			return nil, fmt.Errorf("unmarshal source spec: %w", err)
		}
		baseName := opts.CreateOpts.Name
		if baseName == "" {
			baseName = src.Name() + "-clone"
		}
		cloneName := baseName
		if copies > 1 {
			cloneName = fmt.Sprintf("%s-%d", baseName, i)
		}
		cloneNames[i] = cloneName
		copySpec.Hostname = cloneName
		if copySpec.Root == nil {
			copySpec.Root = &spec.Root{}
		}
		copySpec.Root.Path = cloneRootfsRel[i]
		if copySpec.Annotations == nil {
			copySpec.Annotations = map[string]string{}
		}
		copySpec.Annotations["io.podman.tfork.source-id"] = src.ID()
		copySpec.Annotations["io.podman.tfork.clone-id"] = cloneID
		copySpec.Annotations["io.podman.tfork.batch-id"] = batchID
		copySpec.Annotations["io.podman.tfork.copy-index"] = fmt.Sprintf("%d", i)

		srcPIDForVol, _ := src.PID()
		vols, err := tforkSnapshotVolumes(copySpec, bundleDir, i, copies, srcPIDForVol)
		if err != nil {
			return nil, fmt.Errorf("tfork volume snapshot for copy %d: %w", i, err)
		}
		perCopyVolMounts[i] = vols

		if opts.SharedUsr {
			usrEntry := tforkInjectSharedUsrMount(copySpec, srcRootfs)
			perCopyVolMounts[i] = append(perCopyVolMounts[i], usrEntry)
		}

		cloneSpecs[i] = copySpec

		var cfgPath string
		if copies == 1 {
			cfgPath = filepath.Join(bundleDir, "config.json")
		} else {
			cfgPath = filepath.Join(bundleDir, fmt.Sprintf("config-%d.json", i))
		}
		cb, err := json.MarshalIndent(copySpec, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal clone %d spec: %w", i, err)
		}
		if err := os.WriteFile(cfgPath, cb, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", cfgPath, err)
		}
	}

	if copies > 1 {
		src0 := filepath.Join(bundleDir, "config-0.json")
		dst := filepath.Join(bundleDir, "config.json")
		data, err := os.ReadFile(src0)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", src0, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", dst, err)
		}
	}

	logrus.Infof("tfork: batch %s prepared at %s (source=%s, copies=%d)", batchID, bundleDir, src.ID(), copies)

	imgDir := filepath.Join(bundleDir, "img")
	if err := os.MkdirAll(imgDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir img: %w", err)
	}
	txn.setImageDir(imgDir)

	cloneCgroupPaths := make([]string, copies)
	if cfg := src.Config(); cfg != nil {
		for i := 0; i < copies; i++ {
			cgRel := filepath.Join(cfg.CgroupParent, fmt.Sprintf("libpod-%s", cloneIDs[i]))
			cgFS := filepath.Join("/sys/fs/cgroup", cgRel)
			if err := os.MkdirAll(cgFS, 0o755); err != nil {
				return nil, fmt.Errorf("mkdir clone cgroup %s: %w", cgFS, err)
			}
			cloneCgroupPaths[i] = cgRel
		}
	}
	txn.setCgroupPaths(cloneCgroupPaths)

	srcStatePath := fmt.Sprintf("/run/crun/%s/status", src.ID())
	crunArgs := []string{
		"tfork",
		"--bundle", bundleDir,
		"--source-state", srcStatePath,
		"--image-path", imgDir,
	}
	if !useNcopyRestore {
		crunArgs = append(crunArgs, "--tfork-snap-root", cloneRootfsList[0])
		crunArgs = append(crunArgs, "--tfork-snap-mount", "/")
		if cloneCgroupPaths[0] != "" {
			crunArgs = append(crunArgs, "--cgroup-root", cloneCgroupPaths[0])
		}
	} else {
		crunArgs = append(crunArgs, "--tfork-copies", fmt.Sprintf("%d", copies))
		for i, p := range cloneRootfsList {
			crunArgs = append(crunArgs,
				fmt.Sprintf("--tfork-copy=%d::--tfork-snap-root=%s", i, p))
			crunArgs = append(crunArgs,
				fmt.Sprintf("--tfork-copy=%d::--tfork-snap-mount=/", i))
		}
		if cloneCgroupPaths[0] != "" {
			for i, p := range cloneCgroupPaths {
				if p == "" {
					continue
				}
				crunArgs = append(crunArgs,
					fmt.Sprintf("--tfork-copy=%d::--cgroup-root=%s", i, p))
			}
		}
		if len(perCopyVolMounts[0]) > 0 {
			src0ByDest := make(map[string]string, len(perCopyVolMounts[0]))
			for _, m := range perCopyVolMounts[0] {
				src0ByDest[m.Dest] = m.Source
			}
			for i := 1; i < copies; i++ {
				for _, m := range perCopyVolMounts[i] {
					s0, ok := src0ByDest[m.Dest]
					if !ok {
						logrus.Warnf("tfork: copy %d volume dest %q has no copy-0 counterpart, skipping override", i, m.Dest)
						continue
					}
					if s0 == m.Source {
						continue
					}
					crunArgs = append(crunArgs,
						fmt.Sprintf("--tfork-copy=%d::--external mnt[%s]:%s", i, s0, m.Source))
				}
			}
		}
	}
	srcPIDForSkip, _ := src.PID()
	skipMnts := tforkBuildSkipMnts(srcPIDForSkip)
	for _, m := range skipMnts {
		crunArgs = append(crunArgs, "--skip-mnt", m)
	}
	switch opts.Persistent {
	case "":
	case "async":
		crunArgs = append(crunArgs, "--tfork-memdump-async")
	case "sync":
		crunArgs = append(crunArgs, "--tfork-memdump")
	default:
		return nil, fmt.Errorf("invalid --persistent value %q (must be \"async\" or \"sync\")", opts.Persistent)
	}
	if opts.TforkNetworkLock == "" {
		opts.TforkNetworkLock = "nftables"
	}
	switch opts.TforkNetworkLock {
	case "iptables", "nftables":
		crunArgs = append(crunArgs, "--network-lock", opts.TforkNetworkLock)
	default:
		return nil, fmt.Errorf("invalid --tfork-network-lock value %q (must be \"iptables\" or \"nftables\")", opts.TforkNetworkLock)
	}
	dumpdHolderPid := 0
	var dumpdHolderStartTime uint64
	if opts.Persistent == "async" {
		hpid, hstart, herr := spawnTforkDumpdHolder()
		if herr != nil {
			return nil, fmt.Errorf("spawn tfork-dumpd-holder: %w", herr)
		}
		dumpdHolderPid = hpid
		dumpdHolderStartTime = hstart
		defer func() {
			if retErr != nil && dumpdHolderPid > 0 {
				_ = syscall.Kill(dumpdHolderPid, syscall.SIGKILL)
				logrus.Warnf("tfork: clone setup failed (%v); killed dumpd-holder pid=%d",
					retErr, dumpdHolderPid)
			}
		}()
		logrus.Infof("tfork: dumpd-holder pid=%d start_time=%d (lifetime tied to clone %s)",
			dumpdHolderPid, dumpdHolderStartTime, cloneIDs[0])
	}
	if opts.TforkGhostLimit > 0 {
		crunArgs = append(crunArgs, "--tfork-ghost-limit", fmt.Sprintf("%d", opts.TforkGhostLimit))
	}
	if opts.TforkTCPClose {
		crunArgs = append(crunArgs, "--tfork-tcp-close")
	}
	if opts.TforkFullMemcopy {
		crunArgs = append(crunArgs, "--tfork-full-memcopy")
	}
	parentCloneID := ""
	parentImgDir := ""
	if opts.WithPrevious {
		parent, err := ic.Libpod.FindLatestDoneTforkChild(src.ID())
		if err != nil {
			return nil, fmt.Errorf("--with-previous: scan for chain parent: %w", err)
		}
		if parent == nil {
			return nil, fmt.Errorf("--with-previous: no prior done persistent clone of source %q to chain from", src.ID())
		}
		parentCloneID = parent.ID()
		parentImgDir = parent.TforkImgDir()
		if parentImgDir == "" {
			return nil, fmt.Errorf("--with-previous: chain parent %s has no recorded image-dir", parentCloneID)
		}
		crunArgs = append(crunArgs, "--parent-path", parentImgDir)
		logrus.Infof("tfork: --with-previous chains off clone %s (imgDir=%s)", parentCloneID, parentImgDir)
	}
	if err := tforkInjectFault("before_restore"); err != nil {
		return nil, err
	}

	cloneLogPaths := make([]string, copies)
	cloneConmonPids := make([]int, copies)
	clonePerCopyBundleDirs := make([]string, copies)

	srcPIDForFD, _ := src.PID()
	inheritFds, externals, ttySrcFds, fdErr := buildInheritFdArgs(srcPIDForFD)
	if fdErr != nil {
		logrus.Warnf("tfork: cannot discover source fd KEYs (%v); clone stdio will inherit source's", fdErr)
	}
	defer func() {
		for _, f := range ttySrcFds {
			f.Close()
		}
	}()
	hasTTY := len(ttySrcFds) > 0
	// Keep the legacy single-copy conmon bootstrap opt-in because it can fail
	// before crun starts and report only `conmon reported pid=-1`.
	useConmon := copies == 1 && useSingleCopyConmon

	if useConmon {
		if socketPurgeRead != nil {
			purgeErr := waitSocketPurge()
			_ = socketPurgeRead.Close()
			socketPurgeRead = nil
			if purgeErr != nil {
				return nil, fmt.Errorf("purge clone sockets before restore: %w", purgeErr)
			}
		}
		conmonInheritFds := inheritFds
		if hasTTY {
			conmonInheritFds = filterOutTtyInheritFds(inheritFds)
		}
		logPath := filepath.Join(bundleDir, "clone.log")
		conmonPid, err := spawnConmonForTfork(ctx, conmonForTforkOpts{
			cloneID:        cloneIDs[0],
			cloneName:      cloneNames[0],
			bundleDir:      bundleDir,
			imgDir:         imgDir,
			logPath:        logPath,
			srcStatePath:   srcStatePath,
			tforkSnapRoot:  cloneRootfsList[0],
			skipMnts:       skipMnts,
			inheritFds:     conmonInheritFds,
			externals:      externals,
			terminal:       hasTTY,
			persistent:     opts.Persistent,
			parentImgDir:   parentImgDir,
			ghostLimit:     opts.TforkGhostLimit,
			tcpClose:       opts.TforkTCPClose,
			fullMemcopy:    opts.TforkFullMemcopy,
			networkLock:    opts.TforkNetworkLock,
			cgroupRoot:     cloneCgroupPaths[0],
			dumpdHolderPid: dumpdHolderPid,
		})
		if err != nil {
			return nil, fmt.Errorf("spawn conmon for tfork: %w", err)
		}
		cloneLogPaths[0] = logPath
		cloneConmonPids[0] = conmonPid
		txn.trackPID(conmonPid, "conmon")
		logrus.Infof("tfork: clone %s up via conmon pid=%d; log=%s", cloneIDs[0], conmonPid, logPath)
	} else {
		directArgs := append([]string{}, crunArgs...)
		eventReadiness := os.Getenv("PODMAN_TFORK_EVENT_READINESS") == "1"
		var sourceDetachedRead *os.File
		var sourceDetachedWrite *os.File
		var sourceDetachedDone chan error
		if eventReadiness {
			var err error
			sourceDetachedRead, sourceDetachedWrite, err = os.Pipe()
			if err != nil {
				return nil, fmt.Errorf("create source-detached event pipe: %w", err)
			}
			defer func() {
				if sourceDetachedRead != nil {
					_ = sourceDetachedRead.Close()
				}
				if sourceDetachedWrite != nil {
					_ = sourceDetachedWrite.Close()
				}
			}()
		}
		if dumpdHolderPid > 0 {
			directArgs = append(directArgs,
				fmt.Sprintf("--tfork-dumpd-parent=%d", dumpdHolderPid))
		}
		var perCopyExtraFiles []*os.File
		var perCopyReadEnds []*os.File
		var perCopyArgs []string
		skipTtySrcFds := useNcopyRestore && hasTTY
		if useNcopyRestore {
			ifdsForPerCopy, stdioKeys := splitStdioInheritFds(inheritFds)
			inheritFds = ifdsForPerCopy
			extraFDBase := 3
			if !skipTtySrcFds {
				extraFDBase += len(ttySrcFds)
			}
			for i := 0; i < copies; i++ {
				files, readEnd, err := allocPerCopyStdio(hasTTY)
				if err != nil {
					for _, f := range perCopyExtraFiles {
						f.Close()
					}
					for _, f := range perCopyReadEnds {
						f.Close()
					}
					return nil, fmt.Errorf("alloc per-copy %d stdio: %w", i, err)
				}
				perCopyExtraFiles = append(perCopyExtraFiles, files...)
				perCopyReadEnds = append(perCopyReadEnds, readEnd)
				crunFD := extraFDBase + i
				perCopyArgs = append(perCopyArgs, buildPerCopyInheritFdArgs(i, crunFD, stdioKeys))
			}
		}
		for _, fd := range inheritFds {
			directArgs = append(directArgs, "--inherit-fd", fd)
		}
		for _, ext := range externals {
			directArgs = append(directArgs, "--external", ext)
		}
		for _, pcArg := range perCopyArgs {
			directArgs = append(directArgs, pcArg)
		}
		nextExtraFD := 3 + len(perCopyExtraFiles)
		if hasTTY && !skipTtySrcFds {
			nextExtraFD += len(ttySrcFds)
		}
		if socketPurgeRead != nil {
			directArgs = append(directArgs, "--tfork-pre-restore-fd", strconv.Itoa(nextExtraFD))
			nextExtraFD++
		}
		if sourceDetachedWrite != nil {
			directArgs = append(directArgs, "--tfork-source-detached-fd", strconv.Itoa(nextExtraFD))
		}
		directArgs = append(directArgs, cloneIDs[0])
		crunCmd := exec.Command(defaultCrunPath, directArgs...)
		crunCmd.Stdin = nil
		if hasTTY && !skipTtySrcFds {
			crunCmd.ExtraFiles = append(crunCmd.ExtraFiles, ttySrcFds...)
		}
		if len(perCopyExtraFiles) > 0 {
			crunCmd.ExtraFiles = append(crunCmd.ExtraFiles, perCopyExtraFiles...)
		}
		if socketPurgeRead != nil {
			crunCmd.ExtraFiles = append(crunCmd.ExtraFiles, socketPurgeRead)
		}
		if sourceDetachedWrite != nil {
			crunCmd.ExtraFiles = append(crunCmd.ExtraFiles, sourceDetachedWrite)
		}
		logPath := filepath.Join(bundleDir, "crun-tfork.log")
		logF, err := os.Create(logPath)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", logPath, err)
		}
		crunCmd.Stdout = logF
		crunCmd.Stderr = logF
		if err := crunCmd.Start(); err != nil {
			logF.Close()
			return nil, fmt.Errorf("start crun tfork: %w", err)
		}
		if socketPurgeRead != nil {
			_ = socketPurgeRead.Close()
			socketPurgeRead = nil
		}
		if sourceDetachedWrite != nil {
			_ = sourceDetachedWrite.Close()
			sourceDetachedWrite = nil
			sourceDetachedDone = make(chan error, 1)
			go func() {
				var byte [1]byte
				n, err := sourceDetachedRead.Read(byte[:])
				if err == nil && n != 1 {
					err = fmt.Errorf("short source-detached event read: %d bytes", n)
				}
				sourceDetachedDone <- err
			}()
		}
		txn.trackPID(crunCmd.Process.Pid, "crun-tfork")
		crunDone := make(chan error, 1)
		var crunAborted bool
		defer func() {
			if !crunAborted && retErr != nil {
				tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
			}
		}()
		for _, f := range perCopyExtraFiles {
			_ = f.Close()
		}
		go func() {
			crunDone <- crunCmd.Wait()
			logF.Close()
		}()
		perCopyAttachSocks := make([]*os.File, copies)
		shortBatch := batchID
		if len(shortBatch) > 12 {
			shortBatch = shortBatch[:12]
		}
		runtimeAttachBase := filepath.Join("/run/libpod/tfork", shortBatch)
		txn.setRuntimeBatchDir(runtimeAttachBase)
		for i := 0; i < copies; i++ {
			perCopyBundle := filepath.Join(runtimeAttachBase, fmt.Sprintf("%d", i))
			if err := os.MkdirAll(perCopyBundle, 0o700); err != nil {
				logrus.Warnf("tfork: per-copy %d bundle dir: %v", i, err)
				continue
			}
			clonePerCopyBundleDirs[i] = perCopyBundle
			attachPath := filepath.Join(perCopyBundle, "attach")
			f, err := allocPerCopyAttachSocket(attachPath)
			if err != nil {
				logrus.Warnf("tfork: per-copy %d attach socket: %v (attach disabled for this copy)", i, err)
			} else {
				perCopyAttachSocks[i] = f
			}
		}
		for i, readEnd := range perCopyReadEnds {
			cloneLogPath := ""
			if clonePerCopyBundleDirs[i] != "" {
				cloneLogPath = filepath.Join(clonePerCopyBundleDirs[i], "clone.log")
			} else {
				cloneLogPath = filepath.Join(bundleDir, fmt.Sprintf("clone.%d.log", i))
			}
			helperPID, err := spawnTforkStdioHelper(readEnd, perCopyAttachSocks[i], cloneLogPath, hasTTY)
			if err != nil {
				logrus.Warnf("tfork: per-copy %d stdio-helper spawn: %v", i, err)
			} else {
				txn.trackPID(helperPID, fmt.Sprintf("stdio-helper-%d", i))
			}
			if perCopyAttachSocks[i] != nil {
				_ = perCopyAttachSocks[i].Close()
			}
			cloneLogPaths[i] = cloneLogPath
			_ = readEnd.Close()
		}

		pidFileFor := func(i int) string {
			if !useNcopyRestore {
				return filepath.Join(imgDir, "tfork.pid")
			}
			return filepath.Join(imgDir, fmt.Sprintf("tfork.pid.copy%d", i))
		}
		statePath := fmt.Sprintf("/run/crun/%s/status", cloneIDs[0])
		needState := !useNcopyRestore
		cloneReadyTimeout := tforkCloneReadyTimeoutFromEnv()
		deadline := time.Now().Add(cloneReadyTimeout)
		readyCopies := 0
		stateReady := !needState
		crunExited := false
		var crunErr error
		if eventReadiness {
			timer := time.NewTimer(cloneReadyTimeout)
			defer timer.Stop()
			sourceDetached := false
			for !crunExited || !sourceDetached {
				select {
				case detachErr := <-sourceDetachedDone:
					if detachErr != nil {
						tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
						crunAborted = true
						return nil, fmt.Errorf("wait for tfork source-detached event: %w; see %s", detachErr, logPath)
					}
					sourceDetached = true
					if err := txn.restoreSourceOnce(); err != nil {
						tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
						crunAborted = true
						return nil, fmt.Errorf("early thaw at tfork source-detached event: %w", err)
					}
					logrus.Infof("tfork: source thawed at CRIU source-detached event")
				case crunErr = <-crunDone:
					crunExited = true
					if crunErr != nil {
						tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
						crunAborted = true
						return nil, fmt.Errorf("crun tfork failed before event readiness: %w; see %s", crunErr, logPath)
					}
				case <-timer.C:
					tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
					crunAborted = true
					return nil, fmt.Errorf("timeout waiting %s for tfork source-detached and runtime-exit events; see %s",
						cloneReadyTimeout, logPath)
				}
			}

			readyCopies = 0
			for i := 0; i < copies; i++ {
				if _, err := os.Stat(pidFileFor(i)); err == nil {
					readyCopies++
				}
			}
			if needState {
				_, err := os.Stat(statePath)
				stateReady = err == nil
			}
			if readyCopies < copies || !stateReady {
				return nil, fmt.Errorf("crun exited successfully but clone readiness artifacts are incomplete: pidfiles=%d/%d stateReady=%v; see %s",
					readyCopies, copies, stateReady, logPath)
			}
		} else {
			for readyCopies < copies || !stateReady {
				if !crunExited {
					select {
					case crunErr = <-crunDone:
						crunExited = true
					default:
					}
				}
				readyCopies = 0
				for i := 0; i < copies; i++ {
					if _, err := os.Stat(pidFileFor(i)); err == nil {
						readyCopies++
					}
				}
				if needState && !stateReady {
					if _, err := os.Stat(statePath); err == nil {
						stateReady = true
					}
				}
				if readyCopies >= copies && stateReady {
					break
				}
				if crunExited && readyCopies < copies {
					tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
					crunAborted = true
					if purgeErr := waitSocketPurge(); purgeErr != nil {
						return nil, fmt.Errorf("purge clone sockets before restore: %w", purgeErr)
					}
					return nil, fmt.Errorf("crun tfork exited before %d clones came up (got %d); see %s",
						copies, readyCopies, logPath)
				}
				if time.Now().After(deadline) {
					tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
					crunAborted = true
					return nil, fmt.Errorf("timeout waiting for %d tfork.pid* files in %s (got %d, stateReady=%v); see %s",
						copies, imgDir, readyCopies, stateReady, logPath)
				}
				time.Sleep(tforkClonePollInterval)
			}
			if !crunExited {
				select {
				case crunErr = <-crunDone:
					crunExited = true
				case <-time.After(cloneReadyTimeout):
					tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
					crunAborted = true
					return nil, fmt.Errorf("timeout waiting %s for crun tfork to finish after %d clones came up; see %s",
						cloneReadyTimeout, copies, logPath)
				}
			}
		}
		if purgeErr := waitSocketPurge(); purgeErr != nil {
			tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
			crunAborted = true
			return nil, fmt.Errorf("purge clone sockets before restore: %w", purgeErr)
		}
		if crunErr != nil {
			tforkAbortCrunCmd(crunCmd, src, bundleDir, copies)
			crunAborted = true
			return nil, fmt.Errorf("crun tfork failed after %d clones came up: %w; see %s",
				copies, crunErr, logPath)
		}
		logrus.Infof("tfork: batch %s up (N=%d); crun-tfork.log at %s", batchID, copies, logPath)
	}
	if err := tforkInjectFault("after_restore"); err != nil {
		return nil, err
	}

	if err := txn.restoreSourceOnce(); err != nil {
		logrus.Warnf("tfork: clones are up, but thawing source cgroup after restore failed: %v", err)
		return nil, fmt.Errorf("thaw source cgroup after tfork restore: %w", err)
	}
	if err := tforkInjectFault("after_thaw"); err != nil {
		return nil, err
	}
	srcPID, err := src.PID()
	if err != nil {
		return nil, fmt.Errorf("read source PID after restore: %w", err)
	}
	if err := tforkPIDRunning(srcPID); err != nil {
		return nil, fmt.Errorf("source is not usable after tfork restore: %w", err)
	}

	srcCfg := src.Config()
	if srcCfg == nil {
		return nil, fmt.Errorf("source %q: could not read libpod config", src.ID())
	}
	visibleCloneIDs := make([]string, 0, requestedCopies)
	visibleClones := make([]entities.TforkCloneMetadata, 0, requestedCopies)
	for i, cloneID := range cloneIDs {
		clonePID, err := readTforkClonePID(cloneID, imgDir, i, copies, useNcopyRestore)
		if err != nil {
			return nil, fmt.Errorf("read clone %d PID: %w", i, err)
		}
		txn.trackPID(clonePID, fmt.Sprintf("clone-init-%d", i))
		if err := tforkPIDRunning(clonePID); err != nil {
			return nil, fmt.Errorf("clone %d is not running before publication: %w", i, err)
		}
		clonePIDStartTime, err := libpod.ReadProcStartTime(clonePID)
		if err != nil {
			return nil, fmt.Errorf("read clone %d PID start time: %w", i, err)
		}
		for _, injection := range fileInjections[i] {
			if err := tforkInjectFileIntoProcessRoot(clonePID, injection); err != nil {
				return nil, fmt.Errorf("inject clone %d file %s: %w", i, injection.destination, err)
			}
		}
		cloneCfg, err := buildCloneContainerConfig(srcCfg, cloneID, cloneNames[i], cloneRootfsList[i], cloneSpecs[i])
		if err != nil {
			return nil, fmt.Errorf("build clone %d config: %w", i, err)
		}
		cloneCfg.TforkInitPIDStartTime = clonePIDStartTime
		if len(srcCfg.PortMappings) > 0 {
			clonePorts, err := buildClonePortMappings(srcCfg.PortMappings)
			if err != nil {
				return nil, fmt.Errorf("build clone %d port mappings: %w", i, err)
			}
			cloneCfg.PortMappings = clonePorts
		}
		if cloneLogPaths[i] != "" {
			cloneCfg.LogPath = cloneLogPaths[i]
			cloneCfg.LogDriver = define.KubernetesLogging
		}
		if cloneConmonPids[i] != 0 {
			cloneCfg.ConmonPidFile = filepath.Join(bundleDir, "conmon.pid")
			cloneCfg.ExternalBundlePath = bundleDir
		} else if clonePerCopyBundleDirs[i] != "" {
			cloneCfg.ExternalBundlePath = clonePerCopyBundleDirs[i]
		}
		cloneCfg.TforkImgDir = imgDir
		cloneCfg.TforkPersistent = opts.Persistent
		cloneCfg.TforkSourceID = src.ID()
		cloneCfg.TforkParentClone = parentCloneID
		if i == 0 {
			cloneCfg.TforkDumpdHolderPid = dumpdHolderPid
			cloneCfg.TforkDumpdHolderStartTime = dumpdHolderStartTime
		}
		ctr, err := ic.Libpod.RegisterExternalContainer(ctx, cloneSpecs[i], cloneCfg, clonePID)
		if err != nil {
			return nil, fmt.Errorf("register clone %d (%s) in libpod state: %w", i, cloneID, err)
		}
		txn.addRegistered(ctr)
		if opts.TforkOverlayBtrfs {
			tforkFreezeUpperForRollback(bundleDir, i, copies)
		}
		if cloneConmonPids[i] > 0 {
			if err := ctr.SetConmonPID(cloneConmonPids[i]); err != nil {
				return nil, fmt.Errorf("clone %s SetConmonPID(%d): %w", cloneID, cloneConmonPids[i], err)
			}
		}
		if err := ic.Libpod.SetupExternalCloneNetwork(src, ctr, clonePID); err != nil {
			return nil, fmt.Errorf("clone %s network setup: %w", cloneID, err)
		}
		if cmd := exec.Command("nsenter",
			"-t", strconv.Itoa(clonePID), "-n", "--",
			"sh", "-c", "echo '0 0' > /proc/sys/net/ipv4/ping_group_range"); cmd != nil {
			if out, err := cmd.CombinedOutput(); err != nil {
				logrus.Warnf("tfork: clone %s netns sysctl ping_group_range: %v: %s",
					cloneID, err, strings.TrimSpace(string(out)))
			}
		}
		if err := ctr.MoveExternalCloneToOwnCgroup(clonePID); err != nil {
			return nil, fmt.Errorf("clone %s cgroup migration: %w", cloneID, err)
		}
		if cloneConmonPids[i] == 0 {
			watcherPID, err := spawnTforkExitWatcher(ctx, ic.Libpod, ctr, clonePID)
			if err != nil {
				return nil, fmt.Errorf("tfork: clone %s exit-watcher spawn: %w", cloneID, err)
			}
			txn.trackPID(watcherPID, fmt.Sprintf("exit-watcher-%d", i))
		}
		if err := tforkPIDRunning(clonePID); err != nil {
			return nil, fmt.Errorf("clone %d died during publication: %w", i, err)
		}
		if err := tforkInjectFault(fmt.Sprintf("after_register_%d", i)); err != nil {
			return nil, err
		}
		logrus.Infof("tfork: clone %s (%s) registered in libpod state, pid=%d", cloneID, cloneNames[i], clonePID)
		visibleCloneIDs = append(visibleCloneIDs, cloneID)
		visibleClones = append(visibleClones, entities.TforkCloneMetadata{
			ID:     cloneID,
			Name:   cloneNames[i],
			PID:    clonePID,
			Rootfs: cloneRootfsList[i],
		})
	}

	if err := tforkInjectFault("before_commit"); err != nil {
		return nil, err
	}
	txn.commit()
	return &entities.ContainerCreateReport{
		Id:          strings.Join(visibleCloneIDs, "\n"),
		TforkClones: visibleClones,
	}, nil
}

type tforkFileInjection struct {
	source      string
	destination string
}

func tforkParseFileInjections(specs []string, copies int) (map[int][]tforkFileInjection, error) {
	parsed := make(map[int][]tforkFileInjection)
	for _, spec := range specs {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid --tfork-inject-file %q (expected COPY_INDEX:HOST_PATH:CONTAINER_PATH)", spec)
		}
		copyIndex, err := strconv.Atoi(parts[0])
		if err != nil || copyIndex < 0 || copyIndex >= copies {
			return nil, fmt.Errorf("invalid --tfork-inject-file copy index %q for %d copies", parts[0], copies)
		}
		source := filepath.Clean(parts[1])
		destination := filepath.Clean(parts[2])
		if !filepath.IsAbs(source) || source == string(os.PathSeparator) {
			return nil, fmt.Errorf("tfork injection source must be a non-root absolute path: %q", parts[1])
		}
		if !filepath.IsAbs(destination) || destination == string(os.PathSeparator) {
			return nil, fmt.Errorf("tfork injection destination must be a non-root absolute path: %q", parts[2])
		}
		parsed[copyIndex] = append(parsed[copyIndex], tforkFileInjection{
			source:      source,
			destination: destination,
		})
	}
	return parsed, nil
}

// New destination files inherit Podman's filesystem UID/GID, while an existing
// destination retains its ownership. All destinations are forced to mode 0600;
// this interface intentionally does not provide ownership or mode overrides.
func tforkInjectFileIntoProcessRoot(pid int, injection tforkFileInjection) error {
	const maximumInjectionSize = 1 << 20
	sourceFD, err := unix.Open(injection.source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open source %s: %w", injection.source, err)
	}
	source := os.NewFile(uintptr(sourceFD), injection.source)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat source %s: %w", injection.source, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maximumInjectionSize {
		return fmt.Errorf("source must be a regular file no larger than %d bytes", maximumInjectionSize)
	}

	root := filepath.Join("/proc", strconv.Itoa(pid), "root")
	parent, err := pathrs.OpenInRoot(root, filepath.Dir(injection.destination))
	if err != nil {
		return fmt.Errorf("open destination parent: %w", err)
	}
	defer parent.Close()
	destinationFD, err := unix.Openat(
		int(parent.Fd()),
		filepath.Base(injection.destination),
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	destination := os.NewFile(uintptr(destinationFD), injection.destination)
	defer destination.Close()
	if err := destination.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod destination: %w", err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("copy payload: %w", err)
	}
	return nil
}

type tforkCgroupFreezer struct {
	root       string
	statePath  string
	eventsPath string
	version    string
}

func tforkFreezeSourceCgroup(src *libpod.Container, timeout time.Duration) (func() error, error) {
	if src == nil {
		return nil, fmt.Errorf("source container is nil")
	}
	cgPath, err := src.CgroupPath()
	if err != nil {
		return nil, fmt.Errorf("read source cgroup path: %w", err)
	}
	cgPath = strings.TrimPrefix(filepath.Clean(cgPath), string(os.PathSeparator))
	if cgPath == "" || cgPath == "." {
		return nil, fmt.Errorf("source cgroup path is empty")
	}
	freezer, err := tforkSourceCgroupFreezer(cgPath)
	if err != nil {
		return nil, err
	}

	originalFrozen, err := freezer.frozen()
	if err != nil {
		return nil, err
	}
	if err := freezer.freeze(); err != nil {
		return nil, err
	}
	if err := freezer.waitFrozen(true, timeout); err != nil {
		if !originalFrozen {
			_ = freezer.thaw()
		}
		return nil, err
	}
	logrus.Infof("tfork: froze source cgroup for snapshot consistency: %s (%s)", freezer.root, freezer.version)

	thaw := func() error {
		if originalFrozen {
			return freezer.freeze()
		}
		if err := freezer.thaw(); err != nil {
			return err
		}
		if err := freezer.waitFrozen(false, tforkSourceThawTimeout); err != nil {
			return err
		}
		logrus.Infof("tfork: thawed source cgroup after clone restore: %s (%s)", freezer.root, freezer.version)
		return nil
	}
	return thaw, nil
}

func tforkSourceCgroupFreezer(cgPath string) (*tforkCgroupFreezer, error) {
	v2Root := filepath.Join("/sys/fs/cgroup", cgPath)
	v2FreezePath := filepath.Join(v2Root, "cgroup.freeze")
	v2EventsPath := filepath.Join(v2Root, "cgroup.events")
	if _, err := os.Stat(v2FreezePath); err == nil {
		return &tforkCgroupFreezer{
			root:       v2Root,
			statePath:  v2FreezePath,
			eventsPath: v2EventsPath,
			version:    "cgroup v2",
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat %s: %w", v2FreezePath, err)
	}

	v1Root := filepath.Join("/sys/fs/cgroup/freezer", cgPath)
	v1StatePath := filepath.Join(v1Root, "freezer.state")
	if _, err := os.Stat(v1StatePath); err == nil {
		return &tforkCgroupFreezer{
			root:      v1Root,
			statePath: v1StatePath,
			version:   "cgroup v1 freezer",
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat %s: %w", v1StatePath, err)
	}

	return nil, fmt.Errorf("source cgroup freezer not found for %q; expected cgroup v2 %s or cgroup v1 %s",
		cgPath, v2FreezePath, v1StatePath)
}

func (f *tforkCgroupFreezer) frozen() (bool, error) {
	data, err := os.ReadFile(f.statePath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", f.statePath, err)
	}
	frozen, ok := f.parseFrozen(data)
	if !ok {
		return false, fmt.Errorf("could not parse frozen state from %s", f.statePath)
	}
	return frozen, nil
}

func (f *tforkCgroupFreezer) freeze() error {
	value := []byte("1")
	if f.version == "cgroup v1 freezer" {
		value = []byte("FROZEN")
	}
	if err := os.WriteFile(f.statePath, value, 0o644); err != nil {
		return fmt.Errorf("write %s=%s: %w", f.statePath, value, err)
	}
	return nil
}

func (f *tforkCgroupFreezer) thaw() error {
	value := []byte("0")
	if f.version == "cgroup v1 freezer" {
		value = []byte("THAWED")
	}
	if err := os.WriteFile(f.statePath, value, 0o644); err != nil {
		return fmt.Errorf("write %s=%s: %w", f.statePath, value, err)
	}
	return nil
}

func (f *tforkCgroupFreezer) waitFrozen(wantFrozen bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		path := f.statePath
		if f.eventsPath != "" {
			path = f.eventsPath
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		frozen, ok := f.parseFrozen(data)
		if ok && frozen == wantFrozen {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting %s for %s to report frozen=%t", timeout, path, wantFrozen)
		}
		time.Sleep(tforkCgroupPollInterval)
	}
}

func (f *tforkCgroupFreezer) parseFrozen(data []byte) (bool, bool) {
	if f.version == "cgroup v1 freezer" {
		switch strings.TrimSpace(string(data)) {
		case "FROZEN":
			return true, true
		case "THAWED":
			return false, true
		}
		return false, false
	}

	switch strings.TrimSpace(string(data)) {
	case "0":
		return false, true
	case "1":
		return true, true
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "frozen" {
			switch fields[1] {
			case "0":
				return false, true
			case "1":
				return true, true
			}
		}
	}
	return false, false
}

func spawnTforkDumpdHolder() (int, uint64, error) {
	cmd := exec.Command("setsid", "bash", "-c",
		"sleep infinity & while wait -n 2>/dev/null; do :; done")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("start dumpd-holder: %w", err)
	}
	pid := cmd.Process.Pid
	startTime, stErr := libpod.ReadProcStartTime(pid)
	if stErr != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return 0, 0, fmt.Errorf("read dumpd-holder /proc/%d/stat: %w", pid, stErr)
	}
	if err := cmd.Process.Release(); err != nil {
		logrus.Warnf("tfork: dumpd-holder Process.Release(): %v", err)
	}
	return pid, startTime, nil
}

func tforkAbortCrunCmd(crunCmd *exec.Cmd, src *libpod.Container, bundleDir string, copies int) {
	if crunCmd != nil && crunCmd.Process != nil {
		protected := make(map[int]bool)
		if src != nil {
			if srcPID, err := src.PID(); err == nil && srcPID > 0 {
				protected[srcPID] = true
				for _, pid := range tforkCollectDescendants(srcPID) {
					protected[pid] = true
				}
			}
		}
		toKill := tforkCollectDescendants(crunCmd.Process.Pid)
		// Give CRIU's service and restore helpers a chance to unwind ptrace,
		// parasite, namespace, and cgyard state before killing their parent.
		// Never signal a source-tree PID even if transient reparenting makes it
		// appear below the runtime.
		for i := len(toKill) - 1; i >= 0; i-- {
			if !protected[toKill[i]] {
				_ = syscall.Kill(toKill[i], syscall.SIGTERM)
			}
		}
		if !tforkWaitPIDGone(crunCmd.Process.Pid, time.Second) {
			for i := len(toKill) - 1; i >= 0; i-- {
				if !protected[toKill[i]] {
					_ = syscall.Kill(toKill[i], syscall.SIGKILL)
				}
			}
			_ = syscall.Kill(crunCmd.Process.Pid, syscall.SIGKILL)
			if !tforkWaitPIDGone(crunCmd.Process.Pid, 3*time.Second) {
				logrus.Warnf("tfork: crun-tfork didn't exit after TERM/KILL escalation — source may still be ptraced")
			}
		}
		for _, pid := range tforkCollectDescendants(crunCmd.Process.Pid) {
			if !protected[pid] {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	if src != nil {
		if cgPath, cerr := src.CgroupPath(); cerr == nil && cgPath != "" {
			freezePath := filepath.Join("/sys/fs/cgroup", cgPath, "cgroup.freeze")
			if data, err := os.ReadFile(freezePath); err == nil && strings.TrimSpace(string(data)) == "1" {
				if werr := os.WriteFile(freezePath, []byte("0"), 0o644); werr != nil {
					logrus.Warnf("tfork: thaw src cgroup %s: %v", freezePath, werr)
				} else {
					logrus.Infof("tfork: thawed source cgroup after aborted clone: %s", cgPath)
				}
			}
		}
	}
	if bundleDir != "" {
		tforkBestEffortBundleReap(bundleDir, copies)
	}
}

func tforkWaitPIDGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func tforkCollectDescendants(root int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	children := make(map[int][]int, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if rerr != nil {
			continue
		}
		s := string(data)
		idx := strings.LastIndex(s, ") ")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(s[idx+2:])
		if len(fields) < 2 {
			continue
		}
		ppid, perr2 := strconv.Atoi(fields[1])
		if perr2 != nil {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}
	out := []int{}
	queue := []int{root}
	seen := map[int]bool{root: true}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}

func tforkBestEffortBundleReap(bundleDir string, copies int) {
	if os.Getenv("PODMAN_TFORK_NO_REAP") == "1" {
		return
	}
	if mountsData, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(mountsData), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			mp := fields[1]
			if !strings.HasPrefix(mp, bundleDir+"/") {
				continue
			}
			if err := unix.Unmount(mp, unix.MNT_DETACH); err != nil {
				logrus.Debugf("tfork: abort umount %s: %v", mp, err)
			}
		}
	}
	snapRO := filepath.Join(bundleDir, "snap-ro")
	if fi, err := os.Lstat(snapRO); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(snapRO)
		} else {
			_ = exec.Command("btrfs", "property", "set", "-ts", snapRO, "ro", "false").Run()
			if out, derr := exec.Command("btrfs", "subvolume", "delete", snapRO).CombinedOutput(); derr != nil {
				logrus.Debugf("tfork: abort delete snap-ro %s: %s: %v",
					snapRO, strings.TrimSpace(string(out)), derr)
			}
		}
	}
	_ = os.RemoveAll(filepath.Join(bundleDir, "parent-upper-frozen"))
	if entries, derr := os.ReadDir(bundleDir); derr == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() {
				continue
			}
			if !(name == "rootfs" || strings.HasPrefix(name, "rootfs-")) {
				continue
			}
			path := filepath.Join(bundleDir, name)
			if out, berr := exec.Command("btrfs", "subvolume", "delete", path).CombinedOutput(); berr != nil {
				logrus.Debugf("tfork: abort delete rootfs subvol %s: %s: %v",
					path, strings.TrimSpace(string(out)), berr)
			}
		}
	}
	if err := os.RemoveAll(bundleDir); err != nil {
		logrus.Warnf("tfork: abort rm bundle %s: %v", bundleDir, err)
	} else {
		logrus.Infof("tfork: abort reaped bundle %s", bundleDir)
	}
}

func spawnTforkLogTee(readEnd *os.File, logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(logPath), err)
	}
	pyCode := `import sys, os, datetime, io
src = io.open(0, "rb", buffering=0)
dst = open(os.environ["LOG_PATH"], "ab", buffering=0)
while True:
    line = src.readline()
    if not line:
        break
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    # Pad %f (microseconds, 6 digits) to 9 digits + Z (RFC3339Nano).
    ts = ts + "000Z"
    body = line.rstrip(b"\r\n") + b"\n"
    dst.write(ts.encode() + b" stdout F " + body)
`
	cmd := exec.Command("setsid", "python3", "-c", pyCode)
	cmd.Stdin = readEnd
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Env = append(os.Environ(), "LOG_PATH="+logPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start log-tee: %w", err)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	logrus.Debugf("tfork: spawned log-tee for read-fd → %s", logPath)
	return nil
}

func spawnTforkStdioHelper(readEnd *os.File, attachSock *os.File, logPath string, tty bool) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", filepath.Dir(logPath), err)
	}
	pyCode := `import os, sys, asyncio, datetime, socket, io, traceback
LOG_PATH = os.environ["LOG_PATH"]
TTY = os.environ.get("TTY", "0") == "1"
ATTACH_FD = int(os.environ.get("ATTACH_FD", "-1"))

# fd 0 is the master end (pty for tty; pipe-read for non-tty).
master_in_fd = os.dup(0)
master_out_fd = master_in_fd if TTY else -1  # bidir only for tty

# Open log file in append-binary mode.
log_f = open(LOG_PATH, "ab", buffering=0)

# Live-stream broadcast set; clients are (transport, writer) pairs.
clients = set()

def stamp_log(line: bytes) -> bytes:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    ts = ts + "000Z"
    body = line.rstrip(b"\r\n") + b"\n"
    return ts.encode() + b" stdout F " + body

async def reader_loop():
    # Read raw bytes from master in line-oriented chunks for log
    # framing; broadcast each chunk to attached clients verbatim.
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=64 * 1024)
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(master_in_fd, "rb", buffering=0))
    try:
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                break
            # Write to log per-line so framing is sane.
            for line in chunk.splitlines(keepends=True):
                if line:
                    log_f.write(stamp_log(line))
            # Broadcast verbatim to clients.
            dead = []
            for w in list(clients):
                try:
                    w.write(chunk)
                except Exception:
                    dead.append(w)
            for w in dead:
                clients.discard(w)
                try:
                    w.close()
                except Exception:
                    pass
    finally:
        transport.close()
        for w in list(clients):
            try:
                w.close()
            except Exception:
                pass

async def serve_client(reader, writer):
    clients.add(writer)
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            if TTY and master_out_fd >= 0:
                try:
                    os.write(master_out_fd, data)
                except Exception:
                    break
            # else: non-tty — silently drop; attach is read-only.
    finally:
        clients.discard(writer)
        try:
            writer.close()
        except Exception:
            pass

async def main():
    if ATTACH_FD < 0:
        # No attach socket — degrade to plain logging.
        await reader_loop()
        return
    sock = socket.socket(fileno=ATTACH_FD)
    sock.setblocking(False)
    server = await asyncio.start_unix_server(serve_client, sock=sock)
    reader_task = asyncio.create_task(reader_loop())
    try:
        await reader_task
    finally:
        server.close()
        await server.wait_closed()

try:
    asyncio.run(main())
except Exception:
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
`
	args := []string{"setsid", "python3", "-c", pyCode}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = readEnd
	cmd.Stdout = nil
	if helperErr, openErr := os.OpenFile(logPath+".helper.err", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); openErr == nil {
		cmd.Stderr = helperErr
	}
	env := append(os.Environ(),
		"LOG_PATH="+logPath,
		fmt.Sprintf("TTY=%d", boolToInt(tty)),
	)
	attachFD := -1
	if attachSock != nil {
		cmd.ExtraFiles = []*os.File{attachSock}
		attachFD = 3
	}
	env = append(env, fmt.Sprintf("ATTACH_FD=%d", attachFD))
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start stdio-helper: %w", err)
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
		_ = cmd.Process.Release()
	}
	logrus.Debugf("tfork: spawned stdio-helper for read-fd → %s (attach=%v, tty=%v)", logPath, attachSock != nil, tty)
	return pid, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func allocPerCopyAttachSocket(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	_ = os.Remove(path)
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(false)
	_ = os.Chmod(path, 0o600)
	f, err := ln.File()
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("listener.File: %w", err)
	}
	ln.Close()
	return f, nil
}

func spawnTforkExitWatcher(ctx context.Context, rt *libpod.Runtime, ctr *libpod.Container, clonePID int) (int, error) {
	exitDir := "/run/libpod/exits"
	if err := os.MkdirAll(exitDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", exitDir, err)
	}
	exitFile := filepath.Join(exitDir, ctr.ID())
	script := fmt.Sprintf(`while [ -d /proc/%d ]; do sleep 0.2; done; tmp=%s.tmp; printf 137 > "$tmp" && mv "$tmp" %s`, clonePID, exitFile, exitFile)
	cmd := exec.Command("setsid", "sh", "-c", script)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start exit-watcher: %w", err)
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
		_ = cmd.Process.Release()
	}
	logrus.Debugf("tfork: spawned exit-watcher for clone %s (PID %d) → %s", ctr.ID(), clonePID, exitFile)
	return pid, nil
}

func readTforkClonePID(cloneID string, imgDir string, copyIdx, copies int, useNcopyRestore bool) (int, error) {
	statePath := fmt.Sprintf("/run/crun/%s/status", cloneID)
	if data, err := os.ReadFile(statePath); err == nil {
		var st struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(data, &st); err == nil && st.PID != 0 {
			return st.PID, nil
		}
	}
	var pidFile string
	if !useNcopyRestore {
		pidFile = filepath.Join(imgDir, "tfork.pid")
	} else {
		pidFile = filepath.Join(imgDir, fmt.Sprintf("tfork.pid.copy%d", copyIdx))
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, fmt.Errorf("read %s (and crun state %s missing): %w", pidFile, statePath, err)
	}
	rcPID, err := parsePIDBytes(data, pidFile)
	if err != nil {
		return 0, err
	}
	if !useNcopyRestore {
		return rcPID, nil
	}
	initPID, err := readFirstChildPID(rcPID)
	if err != nil {
		logrus.Warnf("tfork: copy %d: cannot find init child of restore-child %d: %v; using restore-child PID instead (rm -f will likely time out)", copyIdx, rcPID, err)
		return rcPID, nil
	}
	return initPID, nil
}

func readFirstChildPID(pid int) (int, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	first := strings.TrimSpace(string(data))
	if first == "" {
		return 0, fmt.Errorf("%s: no children (restore-child died?)", path)
	}
	if idx := strings.IndexByte(first, ' '); idx >= 0 {
		first = first[:idx]
	}
	return parsePIDBytes([]byte(first), path)
}

func parsePIDBytes(data []byte, src string) (int, error) {
	s := strings.TrimSpace(string(data))
	pid := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("parse pid from %s: bad chars in %q", src, s)
		}
		pid = pid*10 + int(ch-'0')
	}
	if pid == 0 {
		return 0, fmt.Errorf("parse pid from %s: empty/zero", src)
	}
	return pid, nil
}

func buildCloneContainerConfig(src *libpod.ContainerConfig, cloneID, cloneName, rootfsAbs string, cloneSpec *spec.Spec) (*libpod.ContainerConfig, error) {
	jb, err := json.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("marshal src config: %w", err)
	}
	cfg := &libpod.ContainerConfig{}
	if err := json.Unmarshal(jb, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal src config: %w", err)
	}

	cfg.ID = cloneID
	cfg.Name = cloneName

	cfg.Rootfs = rootfsAbs
	cfg.RootfsImageID = ""
	cfg.RootfsImageName = ""
	cfg.RawImageName = ""

	cfg.Spec = cloneSpec

	cfg.CreateNetNS = false
	cfg.NetworksDeprecated = nil
	cfg.StaticIP = nil
	cfg.StaticMAC = nil

	cfg.LockID = 0

	cfg.LogPath = ""
	cfg.StaticDir = ""
	cfg.ConmonPidFile = ""
	cfg.PidFile = ""
	cfg.SecretsPath = ""
	cfg.ShmDir = ""

	cfg.Dependencies = nil

	return cfg, nil
}

func buildClonePortMappings(srcMappings []types.PortMapping) ([]types.PortMapping, error) {
	clonePorts := make([]types.PortMapping, 0, len(srcMappings))
	for _, p := range srcMappings {
		hp, err := utils.GetRandomPort()
		if err != nil {
			return nil, fmt.Errorf("allocate host port for container port %d: %w", p.ContainerPort, err)
		}
		clone := p
		clone.HostPort = uint16(hp)
		clonePorts = append(clonePorts, clone)
	}
	return clonePorts, nil
}

func tforkBin(envVar, fallback string) string {
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	return fallback
}

var defaultCrunPath = tforkBin("OS4AGENT_CRUN", "crun")

var defaultConmonPath = tforkBin("OS4AGENT_CONMON", "conmon")

type conmonForTforkOpts struct {
	cloneID        string
	cloneName      string
	bundleDir      string
	imgDir         string
	logPath        string
	srcStatePath   string
	tforkSnapRoot  string
	skipMnts       []string
	inheritFds     []string
	externals      []string
	terminal       bool
	persistent     string
	parentImgDir   string
	ghostLimit     uint
	tcpClose       bool
	fullMemcopy    bool
	networkLock    string
	cgroupRoot     string
	dumpdHolderPid int
}

func splitStdioInheritFds(in []string) (nonStdio []string, stdioKeys []string) {
	for _, e := range in {
		colon := strings.IndexByte(e, ':')
		if colon < 0 {
			nonStdio = append(nonStdio, e)
			continue
		}
		key := e[colon+1:]
		isStdio := strings.HasPrefix(key, "pipe:") ||
			strings.HasPrefix(key, "pipe[") ||
			strings.HasPrefix(key, "tty[")
		if !isStdio {
			nonStdio = append(nonStdio, e)
			continue
		}
		stdioKeys = append(stdioKeys, key)
	}
	return nonStdio, stdioKeys
}

func allocPerCopyStdio(hasTTY bool) (extraFiles []*os.File, readEnd *os.File, err error) {
	if hasTTY {
		master, slave, perr := allocPtyPair()
		if perr != nil {
			return nil, nil, perr
		}
		return []*os.File{slave}, master, nil
	}
	r, w, perr := os.Pipe()
	if perr != nil {
		return nil, nil, perr
	}
	return []*os.File{w}, r, nil
}

func allocPtyPair() (*os.File, *os.File, error) {
	masterFd, err := unix.Open("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	locked := 0
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(masterFd),
		unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&locked))); errno != 0 {
		unix.Close(masterFd)
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %w", errno)
	}
	slaveFd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(masterFd),
		unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY)
	if int(slaveFd) == -1 {
		unix.Close(masterFd)
		return nil, nil, fmt.Errorf("TIOCGPTPEER: %w", errno)
	}
	return os.NewFile(uintptr(masterFd), "tfork-clone-pts-master"),
		os.NewFile(slaveFd, "tfork-clone-pts-slave"),
		nil
}

func buildPerCopyInheritFdArgs(copyIdx int, crunFD int, stdioKeys []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--tfork-copy=%d::", copyIdx)
	first := true
	for _, key := range stdioKeys {
		if !first {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "--inherit-fd fd[%d]:%s", crunFD, key)
		first = false
	}
	return b.String()
}

func filterOutTtyInheritFds(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		colon := strings.IndexByte(e, ':')
		if colon < 0 {
			out = append(out, e)
			continue
		}
		if strings.HasPrefix(e[colon+1:], "tty[") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func buildInheritFdArgs(srcPID int) (inheritFds []string, externals []string, ttySrcFds []*os.File, err error) {
	if srcPID <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid srcPID %d", srcPID)
	}
	seenExt := map[string]bool{}
	for i := 0; i < 3; i++ {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", srcPID, i)
		target, lerr := os.Readlink(linkPath)
		if lerr != nil {
			continue
		}
		if target == "/dev/null" {
			continue
		}
		if strings.HasPrefix(target, "pipe:") {
			inheritFds = append(inheritFds, fmt.Sprintf("%d:%s", i, target))
			continue
		}
		var st unix.Stat_t
		if serr := unix.Stat(linkPath, &st); serr != nil {
			logrus.Warnf("tfork: stat %s: %v (skipping fd %d)", linkPath, serr, i)
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFCHR {
			logrus.Warnf("tfork: source fd %d (target=%s) is not pipe/null/chardev — skipping", i, target)
			continue
		}
		ttyID := fmt.Sprintf("tty[%x:%x]", st.Rdev, st.Dev)
		f, oerr := os.OpenFile(linkPath, os.O_RDWR, 0)
		if oerr != nil {
			f, oerr = os.OpenFile(linkPath, os.O_RDONLY, 0)
			if oerr != nil {
				logrus.Warnf("tfork: open %s for tty inherit: %v", linkPath, oerr)
				continue
			}
		}
		ttySrcFds = append(ttySrcFds, f)
		crunFD := 3 + len(ttySrcFds) - 1
		inheritFds = append(inheritFds, fmt.Sprintf("%d:%s", crunFD, ttyID))
		if !seenExt[ttyID] {
			externals = append(externals, ttyID)
			seenExt[ttyID] = true
		}
	}
	return inheritFds, externals, ttySrcFds, nil
}

func spawnConmonForTfork(ctx context.Context, opts conmonForTforkOpts) (int, error) {
	syncR, syncW, err := newSocketPair()
	if err != nil {
		return 0, fmt.Errorf("create sync pipe: %w", err)
	}
	defer syncR.Close()

	startR, startW, err := newSocketPair()
	if err != nil {
		syncW.Close()
		return 0, fmt.Errorf("create start pipe: %w", err)
	}
	defer startW.Close()

	pidFile := filepath.Join(opts.bundleDir, "container.pid")
	conmonPidFile := filepath.Join(opts.bundleDir, "conmon.pid")
	exitDir := "/run/libpod/exits"
	persistDir := filepath.Join(opts.bundleDir, "persist", opts.cloneID)
	socketDir := filepath.Join(opts.bundleDir, "sockets")
	for _, d := range []string{exitDir, persistDir, socketDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			syncW.Close()
			startR.Close()
			return 0, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	ociLog := filepath.Join(opts.bundleDir, "crun-oci.log")
	args := []string{
		"--api-version", "1",
		"-c", opts.cloneID,
		"-u", opts.cloneID,
		"-r", defaultCrunPath,
		"-b", opts.bundleDir,
		"-p", pidFile,
		"-n", opts.cloneName,
		"--exit-dir", exitDir,
		"--persist-dir", persistDir,
		"--socket-dir-path", socketDir,
		"--full-attach",
		"-l", "k8s-file:" + opts.logPath,
		"--log-level", "debug",
		"--syslog",
		"--conmon-pidfile", conmonPidFile,
		"--tfork",
		"--restore", opts.imgDir,
	}
	if opts.terminal {
		args = append(args, "-t")
	}
	args = append(args,
		"--runtime-arg", "--log-format=json",
		"--runtime-arg", "--log",
		"--runtime-arg", ociLog,
	)
	tforkRuntimeOpts := []string{
		fmt.Sprintf("--source-state=%s", opts.srcStatePath),
		fmt.Sprintf("--tfork-snap-root=%s", opts.tforkSnapRoot),
	}
	for _, m := range opts.skipMnts {
		tforkRuntimeOpts = append(tforkRuntimeOpts, fmt.Sprintf("--skip-mnt=%s", m))
	}
	for _, fd := range opts.inheritFds {
		tforkRuntimeOpts = append(tforkRuntimeOpts, fmt.Sprintf("--inherit-fd=%s", fd))
	}
	for _, ext := range opts.externals {
		tforkRuntimeOpts = append(tforkRuntimeOpts, fmt.Sprintf("--external=%s", ext))
	}
	switch opts.persistent {
	case "":
	case "async":
		tforkRuntimeOpts = append(tforkRuntimeOpts, "--tfork-memdump-async")
	case "sync":
		tforkRuntimeOpts = append(tforkRuntimeOpts, "--tfork-memdump")
	}
	if opts.parentImgDir != "" {
		tforkRuntimeOpts = append(tforkRuntimeOpts, fmt.Sprintf("--parent-path=%s", opts.parentImgDir))
	}
	if opts.ghostLimit > 0 {
		tforkRuntimeOpts = append(tforkRuntimeOpts, fmt.Sprintf("--tfork-ghost-limit=%d", opts.ghostLimit))
	}
	if opts.tcpClose {
		tforkRuntimeOpts = append(tforkRuntimeOpts, "--tfork-tcp-close")
	}
	if opts.fullMemcopy {
		tforkRuntimeOpts = append(tforkRuntimeOpts, "--tfork-full-memcopy")
	}
	if opts.networkLock != "" {
		tforkRuntimeOpts = append(tforkRuntimeOpts,
			fmt.Sprintf("--network-lock=%s", opts.networkLock))
	}
	if opts.cgroupRoot != "" {
		tforkRuntimeOpts = append(tforkRuntimeOpts,
			fmt.Sprintf("--cgroup-root=%s", opts.cgroupRoot))
	}
	if opts.dumpdHolderPid > 0 {
		tforkRuntimeOpts = append(tforkRuntimeOpts,
			fmt.Sprintf("--tfork-dumpd-parent=%d", opts.dumpdHolderPid))
	}
	for _, opt := range tforkRuntimeOpts {
		args = append(args, "--runtime-opt", opt)
	}

	conmonStderrPath := filepath.Join(opts.bundleDir, "conmon-stderr.log")
	conmonStderrF, err := os.Create(conmonStderrPath)
	if err != nil {
		syncW.Close()
		startR.Close()
		return 0, fmt.Errorf("create conmon stderr log: %w", err)
	}

	logrus.Infof("tfork: spawning conmon: %s %s", defaultConmonPath, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, defaultConmonPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = nil
	cmd.Stdout = conmonStderrF
	cmd.Stderr = conmonStderrF
	cmd.ExtraFiles = []*os.File{syncW, startR}
	cmd.Env = append(os.Environ(),
		"_OCI_SYNCPIPE=3",
		"_OCI_STARTPIPE=4",
	)

	if err := cmd.Start(); err != nil {
		syncW.Close()
		startR.Close()
		return 0, fmt.Errorf("start conmon: %w", err)
	}
	syncW.Close()
	startR.Close()

	if _, err := startW.Write([]byte{0}); err != nil {
		logrus.Debugf("tfork: write start pipe: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return 0, fmt.Errorf("conmon parent did not exit cleanly: %w", err)
	}

	pid, perr := readConmonSyncPid(syncR)
	if perr != nil {
		return 0, fmt.Errorf("read PID from conmon sync pipe: %w", perr)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("conmon reported pid=%d", pid)
	}

	conmonPidBytes, err := os.ReadFile(conmonPidFile)
	if err != nil {
		logrus.Debugf("tfork: conmon pidfile missing: %v", err)
		return 0, nil
	}
	conmonPid := 0
	for _, ch := range strings.TrimSpace(string(conmonPidBytes)) {
		if ch < '0' || ch > '9' {
			break
		}
		conmonPid = conmonPid*10 + int(ch-'0')
	}
	return conmonPid, nil
}

func newSocketPair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func readConmonSyncPid(pipe *os.File) (int, error) {
	rdr := bufio.NewReader(pipe)
	b, err := rdr.ReadBytes('\n')
	if err != nil && len(b) == 0 {
		return 0, fmt.Errorf("read sync pipe: %w", err)
	}
	var sync struct {
		Data    int    `json:"data"`
		Message string `json:"message,omitempty"`
	}
	if jerr := json.Unmarshal(b, &sync); jerr != nil {
		return 0, fmt.Errorf("parse %q: %w", string(b), jerr)
	}
	if sync.Message != "" {
		logrus.Debugf("conmon sync message: %s", sync.Message)
	}
	return sync.Data, nil
}

var tforkPodmanSkipMnts = []string{
	"/proc/interrupts",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/acpi",
	"/proc/scsi",
	"/sys/devices/virtual/powercap",
	"/sys/firmware",
	"/sys/fs/cgroup",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/hostname",
	"/run/.containerenv",
}

func tforkSetupOverlayRootfs(snapRO, bundleDir string, copyIdx, copies int, mergedDir string) error {
	var upperRel, workRel string
	if copies == 1 {
		upperRel = "upper"
		workRel = "work"
	} else {
		upperRel = fmt.Sprintf("upper-%d", copyIdx)
		workRel = fmt.Sprintf("work-%d", copyIdx)
	}
	upper := filepath.Join(bundleDir, upperRel)
	work := filepath.Join(bundleDir, workRel)

	if err := os.MkdirAll(upper, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", upper, err)
	}
	if fi, err := os.Stat(snapRO); err == nil {
		if err := os.Chmod(upper, fi.Mode().Perm()); err != nil {
			return fmt.Errorf("chmod %s to match snap-ro: %w", upper, err)
		}
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", work, err)
	}
	if err := os.MkdirAll(mergedDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mergedDir, err)
	}

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,index=off",
		snapRO, upper, work)
	if out, err := exec.Command("mount", "-t", "overlay",
		"-o", opts, "overlay", mergedDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mount overlay %s (opts=%s): %s: %w",
			mergedDir, opts, strings.TrimSpace(string(out)), err)
	}
	logrus.Infof("tfork: overlay rootfs %s (lower=%s upper=%s)",
		mergedDir, snapRO, upper)
	return nil
}

func tforkSetupSnapSubvolRootfs(parentSubvol, bundleDir string, copyIdx, copies int, mergedDir string) error {
	if err := os.RemoveAll(mergedDir); err != nil {
		return fmt.Errorf("clear stale %s: %w", mergedDir, err)
	}
	if out, err := exec.Command("btrfs", "subvolume", "snapshot",
		parentSubvol, mergedDir).CombinedOutput(); err != nil {
		return fmt.Errorf("btrfs snapshot %s -> %s: %s: %w",
			parentSubvol, mergedDir, strings.TrimSpace(string(out)), err)
	}
	logrus.Infof("tfork: snap-subvol rootfs %s (writable snapshot of %s)",
		mergedDir, parentSubvol)
	return nil
}

func tforkFreezeUpperForRollback(bundleDir string, copyIdx, copies int) {
	var upperRel, snapRel string
	if copies == 1 {
		upperRel = "upper"
		snapRel = "snap"
	} else {
		upperRel = fmt.Sprintf("upper-%d", copyIdx)
		snapRel = fmt.Sprintf("snap-%d", copyIdx)
	}
	upper := filepath.Join(bundleDir, upperRel)
	snap := filepath.Join(bundleDir, snapRel)
	if _, err := os.Stat(snap); err == nil {
		return
	}
	if err := os.MkdirAll(snap, 0o755); err != nil {
		logrus.Warnf("tfork: rollback freeze mkdir %s for copy %d: %v",
			snap, copyIdx, err)
		return
	}
	if out, err := exec.Command("cp", "-a", "--reflink=always",
		upper+"/.", snap+"/").CombinedOutput(); err != nil {
		logrus.Warnf("tfork: rollback freeze (reflink-cp) failed for copy %d (%s -> %s): %s: %v",
			copyIdx, upper, snap, strings.TrimSpace(string(out)), err)
		_ = os.RemoveAll(snap)
		return
	}
	logrus.Infof("tfork: rollback snapshot %s frozen for copy %d", snap, copyIdx)
}

func tforkTeardownOverlayRootfs(bundleDir string, copyIdx, copies int, mergedDir string) error {
	_ = exec.Command("umount", mergedDir).Run()
	var upperRel, workRel string
	if copies == 1 {
		upperRel = "upper"
		workRel = "work"
	} else {
		upperRel = fmt.Sprintf("upper-%d", copyIdx)
		workRel = fmt.Sprintf("work-%d", copyIdx)
	}
	upper := filepath.Join(bundleDir, upperRel)
	work := filepath.Join(bundleDir, workRel)
	if _, err := os.Stat(upper); err == nil {
		out, err := exec.Command("btrfs", "subvolume", "delete", upper).CombinedOutput()
		if err != nil {
			if rerr := os.RemoveAll(upper); rerr != nil {
				return fmt.Errorf("teardown upper %s: btrfs delete %s: %w; rm: %v",
					upper, strings.TrimSpace(string(out)), err, rerr)
			}
		}
	}
	_ = os.RemoveAll(work)
	_ = os.Remove(mergedDir)
	return nil
}

func tforkResolveOverlayLayers(mergedDir string) (lowerdir, upperdir string, err error) {
	canon, err := filepath.Abs(mergedDir)
	if err != nil {
		return "", "", fmt.Errorf("abs %s: %w", mergedDir, err)
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", "", fmt.Errorf("open mountinfo: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 3 {
			continue
		}
		mountpoint := left[4]
		fstype := right[0]
		superOpts := right[2]
		if fstype != "overlay" {
			continue
		}
		if mountpoint != canon {
			continue
		}
		for _, kv := range strings.Split(superOpts, ",") {
			if rest, ok := strings.CutPrefix(kv, "lowerdir="); ok {
				lowerdir = strings.Split(rest, ":")[0]
			} else if rest, ok := strings.CutPrefix(kv, "upperdir="); ok {
				upperdir = rest
			}
		}
		if lowerdir == "" || upperdir == "" {
			return "", "", fmt.Errorf("overlay mounted at %s but lowerdir/upperdir missing in opts %q",
				canon, superOpts)
		}
		return lowerdir, upperdir, nil
	}
	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("scan mountinfo: %w", err)
	}
	return "", "", fmt.Errorf("no overlay mount at %s in /proc/self/mountinfo", canon)
}

func tforkSetupOverlayRootfsFromParent(snapRO, parentUpperFrozen, bundleDir string, copyIdx, copies int, mergedDir string) error {
	var upperRel, workRel string
	if copies == 1 {
		upperRel = "upper"
		workRel = "work"
	} else {
		upperRel = fmt.Sprintf("upper-%d", copyIdx)
		workRel = fmt.Sprintf("work-%d", copyIdx)
	}
	upper := filepath.Join(bundleDir, upperRel)
	work := filepath.Join(bundleDir, workRel)

	if err := os.MkdirAll(upper, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", upper, err)
	}
	if out, err := exec.Command("cp", "-a", "--reflink=always",
		parentUpperFrozen+"/.", upper+"/").CombinedOutput(); err != nil {
		return fmt.Errorf("cp --reflink=always %s -> %s: %s: %w",
			parentUpperFrozen, upper, strings.TrimSpace(string(out)), err)
	}
	if fi, err := os.Stat(snapRO); err == nil {
		if err := os.Chmod(upper, fi.Mode().Perm()); err != nil {
			return fmt.Errorf("chmod %s to match snap-ro: %w", upper, err)
		}
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", work, err)
	}
	if err := os.MkdirAll(mergedDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mergedDir, err)
	}

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,index=off",
		snapRO, upper, work)
	if out, err := exec.Command("mount", "-t", "overlay",
		"-o", opts, "overlay", mergedDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mount overlay %s (opts=%s): %s: %w",
			mergedDir, opts, strings.TrimSpace(string(out)), err)
	}
	logrus.Infof("tfork: overlay rootfs %s (lower=%s upper=%s, seeded from %s)",
		mergedDir, snapRO, upper, parentUpperFrozen)
	return nil
}

func tforkPurgeSockets(rootfs string) error {
	cmd := exec.Command("find", rootfs, "-mindepth", "1", "-type", "s", "-print", "-delete")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("find -type s -delete %s: %s: %w", rootfs, strings.TrimSpace(string(out)), err)
	}
	if len(out) > 0 {
		n := strings.Count(string(out), "\n")
		logrus.Infof("tfork: purged %d unix socket(s) from %s", n, rootfs)
	}
	return nil
}

func tforkPurgeSocketsWithManifest(rootfsList []string, manifestPath string) error {
	if len(rootfsList) == 0 {
		return fmt.Errorf("socket purge requires at least one clone rootfs")
	}
	started := time.Now()
	cmd := exec.Command("find", rootfsList[0], "-mindepth", "1", "-type", "s", "-printf", "%P\\0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("find socket manifest in %s: %s: %w", rootfsList[0], strings.TrimSpace(string(out)), err)
	}
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		return fmt.Errorf("write socket manifest %s: %w", manifestPath, err)
	}

	count := 0
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe socket path %q in %s", rel, manifestPath)
		}
		count++
		for _, rootfs := range rootfsList {
			if err := os.Remove(filepath.Join(rootfs, clean)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove socket %s from %s: %w", clean, rootfs, err)
			}
		}
	}
	logrus.Infof("tfork: socket manifest found %d path(s), applied to %d clone rootfs(es) in %s",
		count, len(rootfsList), time.Since(started))
	return nil
}

// tforkPurgeSocketsAndSignal opens the restore barrier only after every clone
// rootfs has been purged. On any error it writes no byte, so closing barrier
// produces EOF in crun and makes the clone transaction roll back.
func tforkPurgeSocketsAndSignal(rootfsList []string, manifestPath string, barrier *os.File) error {
	if barrier == nil {
		return fmt.Errorf("socket-purge barrier is nil")
	}
	if err := tforkPurgeSocketsWithManifest(rootfsList, manifestPath); err != nil {
		return err
	}
	if _, err := barrier.Write([]byte{1}); err != nil {
		return fmt.Errorf("signal socket-purge completion: %w", err)
	}
	return nil
}

func tforkBuildSkipMnts(srcPID int) []string {
	out := make([]string, 0, len(tforkPodmanSkipMnts)+8)
	seen := make(map[string]struct{}, len(tforkPodmanSkipMnts))
	for _, m := range tforkPodmanSkipMnts {
		out = append(out, m)
		seen[m] = struct{}{}
	}
	if srcPID <= 0 {
		return out
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", srcPID))
	if err != nil {
		logrus.Warnf("tfork: read source mountinfo for skip-mnt extension failed: %v (proceeding with static seed)", err)
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		root, target := fields[3], fields[4]
		switch {
		case root == "/null":
		case root == "/crun/.empty-directory":
		case strings.HasPrefix(root, "/podman/runroot/"):
		default:
			continue
		}
		if target == "/" {
			continue
		}
		if _, dup := seen[target]; dup {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	if err := sc.Err(); err != nil {
		logrus.Warnf("tfork: scan source mountinfo: %v (using partial extension)", err)
	}
	return out
}

type tforkVolMount struct {
	Dest   string
	Source string
}

func tforkSnapshotVolumes(s *spec.Spec, bundleDir string, copyIdx, copies, srcPID int) ([]tforkVolMount, error) {
	if s == nil || srcPID <= 0 {
		return nil, nil
	}
	const volPrefix = "/podman/storage/volumes/"
	var volsDir string
	if copies == 1 {
		volsDir = filepath.Join(bundleDir, "volumes")
	} else {
		volsDir = filepath.Join(bundleDir, fmt.Sprintf("volumes-%d", copyIdx))
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", srcPID))
	if err != nil {
		return nil, fmt.Errorf("open source mountinfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var added []tforkVolMount
	seen := make(map[string]struct{}, 4)
	btrfsRootCache := make(map[string]string, 1)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		majMin, root, target := fields[2], fields[3], fields[4]
		if !strings.HasPrefix(root, volPrefix) {
			continue
		}
		if _, dup := seen[target]; dup {
			continue
		}
		seen[target] = struct{}{}

		tail := root[len(volPrefix):]
		parts := strings.SplitN(tail, "/", 2)
		if len(parts) < 1 || parts[0] == "" {
			logrus.Warnf("tfork: can't extract vol name from root %q, skipping", root)
			continue
		}
		volName := parts[0]

		btrfsHostRoot, ok := btrfsRootCache[majMin]
		if !ok {
			resolved, err := tforkResolveBtrfsHostRoot(majMin)
			if err != nil {
				return nil, fmt.Errorf("vol %s: resolve btrfs host mount for dev %s: %w", volName, majMin, err)
			}
			btrfsRootCache[majMin] = resolved
			btrfsHostRoot = resolved
		}
		srcData := filepath.Join(btrfsHostRoot, root)

		snapDir := filepath.Join(volsDir, volName)
		snapData := filepath.Join(snapDir, "_data")
		if err := os.MkdirAll(volsDir, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", volsDir, err)
		}

		if out, err := exec.Command("btrfs", "subvolume", "snapshot",
			srcData, snapData).CombinedOutput(); err != nil {
			logrus.Infof("tfork: btrfs snapshot %s→%s failed (%s), falling back to reflink-cp",
				srcData, snapData, strings.TrimSpace(string(out)))
			if err := os.MkdirAll(snapDir, 0755); err != nil {
				return nil, fmt.Errorf("mkdir %s: %w", snapDir, err)
			}
			if out, err := exec.Command("cp", "-r", "--reflink=always",
				srcData, snapData).CombinedOutput(); err != nil {
				return nil, fmt.Errorf("cp --reflink %s→%s: %s: %w",
					srcData, snapData, out, err)
			}
		}

		s.Mounts = append(s.Mounts, spec.Mount{
			Destination: target,
			Source:      snapData,
			Type:        "bind",
			Options:     []string{"rbind", "rw"},
		})
		added = append(added, tforkVolMount{Dest: target, Source: snapData})
		logrus.Infof("tfork: volume %s: snapshot %s → %s, spec mount appended (dest=%s)",
			volName, srcData, snapData, target)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan source mountinfo: %w", err)
	}
	return added, nil
}

func tforkResolveBtrfsHostRoot(devMajMin string) (string, error) {
	if env := os.Getenv("PODMAN_TFORK_BTRFS_ROOT"); env != "" {
		return env, nil
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if fields[2] != devMajMin {
			continue
		}
		if fields[3] != "/" {
			continue
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) {
			continue
		}
		if fields[sep+1] != "btrfs" {
			continue
		}
		return fields[4], nil
	}
	return "", fmt.Errorf("no btrfs mount with root=/ for device %s; set PODMAN_TFORK_BTRFS_ROOT to override", devMajMin)
}

func tforkSourceUsrIsBound(srcPID int) (bool, error) {
	if srcPID <= 0 {
		return false, fmt.Errorf("source pid is zero")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", srcPID))
	if err != nil {
		return false, fmt.Errorf("open source mountinfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		if fields[4] == "/usr" {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("scan source mountinfo: %w", err)
	}
	return false, nil
}

func tforkPrepareSharedUsr(srcPID int) error {
	if srcPID <= 0 {
		return fmt.Errorf("source pid is zero")
	}
	bound, err := tforkSourceUsrIsBound(srcPID)
	if err != nil {
		return fmt.Errorf("probe source /usr: %w", err)
	}
	if bound {
		logrus.Infof("tfork: shared-/usr: source pid=%d already has /usr as a mount; reusing", srcPID)
		return nil
	}
	cmd := exec.Command("nsenter", "-m", "-t", fmt.Sprintf("%d", srcPID),
		"mount", "--bind", "/usr", "/usr")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nsenter+mount --bind /usr in src ns: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	logrus.Infof("tfork: shared-/usr: self-bound /usr in source pid=%d mountns", srcPID)
	return nil
}

func tforkInjectSharedUsrMount(s *spec.Spec, srcRootfs string) tforkVolMount {
	srcUsr := filepath.Join(srcRootfs, "usr")
	m := spec.Mount{
		Destination: "/usr",
		Source:      srcUsr,
		Type:        "bind",
		Options:     []string{"rbind", "rw"},
	}
	s.Mounts = append(s.Mounts, m)
	return tforkVolMount{Dest: "/usr", Source: srcUsr}
}
