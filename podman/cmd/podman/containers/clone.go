package containers

import (
	jsonencoding "encoding/json"
	"fmt"
	"os"

	"github.com/containers/podman/v5/cmd/podman/common"
	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/libpod/define"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/spf13/cobra"
)

var (
	cloneDescription = `Creates a copy of an existing container.`

	containerCloneCommand = &cobra.Command{
		Use:               "clone [options] CONTAINER NAME IMAGE",
		Short:             "Clone an existing container",
		Long:              cloneDescription,
		RunE:              clone,
		Args:              cobra.RangeArgs(1, 3),
		ValidArgsFunction: common.AutocompleteClone,
		Example:           `podman container clone container_name new_name image_name`,
	}
)

var (
	ctrClone entities.ContainerCloneOptions
)

func cloneFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	destroyFlagName := "destroy"
	flags.BoolVar(&ctrClone.Destroy, destroyFlagName, false, "destroy the original container")

	runFlagName := "run"
	flags.BoolVar(&ctrClone.Run, runFlagName, false, "run the new container")

	forceFlagName := "force"
	flags.BoolVarP(&ctrClone.Force, forceFlagName, "f", false, "force the existing container to be destroyed")

	liveFlagName := "live"
	flags.BoolVar(&ctrClone.Live, liveFlagName, false, "live-clone the source via CRIU tfork (CoW memory, per-clone rootfs snapshot)")

	copiesFlagName := "copies"
	flags.IntVar(&ctrClone.Copies, copiesFlagName, 0, "number of parallel clones to produce (only with --live; default 1)")

	persistentFlagName := "persistent"
	flags.StringVar(&ctrClone.Persistent, persistentFlagName, "", `persist source memory to clone's image-dir as a backup; one of "async" (default when bare) or "sync" (only with --live)`)
	containerCloneCommand.Flags().Lookup(persistentFlagName).NoOptDefVal = "async"

	withPreviousFlagName := "with-previous"
	flags.BoolVar(&ctrClone.WithPrevious, withPreviousFlagName, false, "chain incremental memdump off most-recent done clone (requires --live + --persistent)")

	sharedUsrFlagName := "shared-usr"
	flags.BoolVar(&ctrClone.SharedUsr, sharedUsrFlagName, false, "share /usr from source rootfs into clone via CRIU ext-mount (collapses per-clone page cache for libraries; requires --live)")

	tforkOverlayBtrfsFlagName := "tfork-overlay-btrfs"
	flags.BoolVar(&ctrClone.TforkOverlayBtrfs, tforkOverlayBtrfsFlagName, false, "use overlay-on-btrfs for per-clone rootfs (default: per-clone btrfs subvolume snapshot; overlay shares lower's page cache across siblings; requires --live)")

	tforkMetadataFlagName := "tfork-metadata"
	flags.BoolVar(&ctrClone.TforkMetadata, tforkMetadataFlagName, false, "print live-clone identity, PID, and rootfs metadata as JSON (only with --live)")

	tforkInjectFileFlagName := "tfork-inject-file"
	flags.StringSliceVar(&ctrClone.TforkInjectFiles, tforkInjectFileFlagName, nil, "inject COPY_INDEX:HOST_PATH:CONTAINER_PATH after live restore and before publication (new files use Podman's UID/GID; existing ownership is preserved; mode is forced to 0600)")

	tforkInjectSourceFileFlagName := "tfork-inject-source-file"
	flags.StringSliceVar(&ctrClone.TforkInjectSourceFiles, tforkInjectSourceFileFlagName, nil, "atomically rotate HOST_PATH:CONTAINER_PATH in the frozen source after clone restore; a committed rotation is not rolled back by later publication failure")

	tforkGhostLimitFlagName := "tfork-ghost-limit"
	flags.UintVar(&ctrClone.TforkGhostLimit, tforkGhostLimitFlagName, 256<<20, "raise CRIU's ghost-file size cap (bytes); GUI apps need >1MiB default (only with --live)")

	tforkTCPCloseFlagName := "tfork-tcp-close"
	flags.BoolVar(&ctrClone.TforkTCPClose, tforkTCPCloseFlagName, true, "dump ESTABLISHED TCP sockets as closed (clone reconnects); set --tfork-tcp-close=false to fall back to CRIU's refuse-on-established default (only with --live)")

	tforkFullMemcopyFlagName := "tfork-full-memcopy"
	flags.BoolVar(&ctrClone.TforkFullMemcopy, tforkFullMemcopyFlagName, false, "ablation: physical-copy anon-private VMAs instead of CoW (for measuring the anon-CoW signal; only with --live)")

	tforkNetworkLockFlagName := "tfork-network-lock"
	flags.StringVar(&ctrClone.TforkNetworkLock, tforkNetworkLockFlagName, "nftables", "network lock backend: iptables or nftables (only with --live)")

	common.DefineCreateDefaults(&ctrClone.CreateOpts)
	common.DefineCreateFlags(cmd, &ctrClone.CreateOpts, entities.CloneMode)
}
func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: containerCloneCommand,
		Parent:  containerCmd,
	})

	cloneFlags(containerCloneCommand)
}

func clone(cmd *cobra.Command, args []string) error {
	switch len(args) {
	case 0:
		return fmt.Errorf("must specify at least 1 argument: %w", define.ErrInvalidArg)
	case 2:
		ctrClone.CreateOpts.Name = args[1]
	case 3:
		ctrClone.CreateOpts.Name = args[1]
		ctrClone.Image = args[2]
		if !cliVals.RootFS {
			rawImageName := args[0]
			name, err := pullImage(cmd, ctrClone.Image, &ctrClone.CreateOpts)
			if err != nil {
				return err
			}
			ctrClone.Image = name
			ctrClone.RawImageName = rawImageName
		}
	}
	if ctrClone.Force && !ctrClone.Destroy {
		return fmt.Errorf("cannot set --force without --destroy: %w", define.ErrInvalidArg)
	}

	if ctrClone.Live {

		if ctrClone.Image != "" {
			return fmt.Errorf("--live cannot take an IMAGE argument; clone reuses the source's rootfs: %w", define.ErrInvalidArg)
		}
		if ctrClone.Destroy || ctrClone.Force {
			return fmt.Errorf("--live is incompatible with --destroy/--force: %w", define.ErrInvalidArg)
		}
		if ctrClone.Copies < 0 {
			return fmt.Errorf("--copies must be >= 0 (0 or 1 = single-copy): %w", define.ErrInvalidArg)
		}
		switch ctrClone.Persistent {
		case "", "async", "sync":
		default:
			return fmt.Errorf(`--persistent must be "async" or "sync", got %q: %w`, ctrClone.Persistent, define.ErrInvalidArg)
		}
		if ctrClone.WithPrevious && ctrClone.Persistent == "" {
			return fmt.Errorf("--with-previous requires --persistent: %w", define.ErrInvalidArg)
		}

		ctrClone.Run = true
	} else {
		if ctrClone.Copies > 0 {
			return fmt.Errorf("--copies requires --live: %w", define.ErrInvalidArg)
		}
		if ctrClone.Persistent != "" {
			return fmt.Errorf("--persistent requires --live: %w", define.ErrInvalidArg)
		}
		if ctrClone.WithPrevious {
			return fmt.Errorf("--with-previous requires --live: %w", define.ErrInvalidArg)
		}
		if ctrClone.SharedUsr {
			return fmt.Errorf("--shared-usr requires --live: %w", define.ErrInvalidArg)
		}
		if ctrClone.TforkOverlayBtrfs {
			return fmt.Errorf("--tfork-overlay-btrfs requires --live: %w", define.ErrInvalidArg)
		}
		if ctrClone.TforkMetadata {
			return fmt.Errorf("--tfork-metadata requires --live: %w", define.ErrInvalidArg)
		}
		if len(ctrClone.TforkInjectFiles) > 0 {
			return fmt.Errorf("--tfork-inject-file requires --live: %w", define.ErrInvalidArg)
		}
		if len(ctrClone.TforkInjectSourceFiles) > 0 {
			return fmt.Errorf("--tfork-inject-source-file requires --live: %w", define.ErrInvalidArg)
		}
	}

	ctrClone.ID = args[0]
	ctrClone.CreateOpts.IsClone = true
	rep, err := registry.ContainerEngine().ContainerClone(registry.Context(), ctrClone)
	if err != nil {
		return err
	}
	if ctrClone.TforkMetadata {
		return jsonencoding.NewEncoder(os.Stdout).Encode(rep.TforkClones)
	}
	fmt.Println(rep.Id)
	return nil
}
