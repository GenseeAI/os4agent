//go:build !remote

package libpod

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/containers/podman/v5/libpod"
	"github.com/containers/podman/v5/libpod/define"
	"github.com/containers/podman/v5/pkg/api/handlers/utils"
	api "github.com/containers/podman/v5/pkg/api/types"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/containers/podman/v5/pkg/domain/infra/abi"
)

const tforkLocalAPIMaxBody = 1 << 20

type tforkLocalAPIRequest struct {
	Name              string   `json:"name"`
	Copies            int      `json:"copies,omitempty"`
	Persistent        string   `json:"persistent,omitempty"`
	WithPrevious      bool     `json:"withPrevious,omitempty"`
	SharedUsr         bool     `json:"sharedUsr,omitempty"`
	OverlayBtrfs      *bool    `json:"overlayBtrfs,omitempty"`
	GhostLimit        uint     `json:"ghostLimit,omitempty"`
	TCPClose          *bool    `json:"tcpClose,omitempty"`
	FullMemcopy       bool     `json:"fullMemcopy,omitempty"`
	NetworkLock       string   `json:"networkLock,omitempty"`
	InjectFiles       []string `json:"injectFiles,omitempty"`
	InjectSourceFiles []string `json:"injectSourceFiles,omitempty"`
}

// TforkCloneLocal exposes the existing live-clone ABI to a root-owned local
// Podman service. It is deliberately opt-in and Unix-socket-only: the normal
// Podman API has no live-clone contract, and this experimental endpoint must
// not silently become available on a TCP listener.
func TforkCloneLocal(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("PODMAN_TFORK_LOCAL_API") != "1" {
		utils.Error(w, http.StatusNotFound, fmt.Errorf("local tfork API is disabled"))
		return
	}
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || localAddr.Network() != "unix" {
		utils.Error(w, http.StatusForbidden, fmt.Errorf("local tfork API requires a Unix-domain listener"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, tforkLocalAPIMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	request := tforkLocalAPIRequest{}
	if err := decoder.Decode(&request); err != nil {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("decode local tfork request: %w", err))
		return
	}
	if request.Name == "" {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("clone name is required"))
		return
	}
	if request.Copies < 0 {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("copies must be non-negative"))
		return
	}
	if request.Persistent == "" {
		request.Persistent = "async"
	}
	if request.Persistent != "async" && request.Persistent != "sync" {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("persistent must be async or sync"))
		return
	}
	if request.WithPrevious && request.Persistent == "" {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("withPrevious requires persistent state"))
		return
	}

	overlayBtrfs := true
	if request.OverlayBtrfs != nil {
		overlayBtrfs = *request.OverlayBtrfs
	}
	tcpClose := true
	if request.TCPClose != nil {
		tcpClose = *request.TCPClose
	}
	if request.GhostLimit == 0 {
		request.GhostLimit = 256 << 20
	}
	if request.NetworkLock == "" {
		request.NetworkLock = "nftables"
	}

	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	containerEngine := abi.ContainerEngine{Libpod: runtime}
	options := entities.ContainerCloneOptions{
		ID:                     utils.GetName(r),
		Live:                   true,
		Run:                    true,
		Copies:                 request.Copies,
		Persistent:             request.Persistent,
		WithPrevious:           request.WithPrevious,
		SharedUsr:              request.SharedUsr,
		TforkOverlayBtrfs:      overlayBtrfs,
		TforkMetadata:          true,
		TforkGhostLimit:        request.GhostLimit,
		TforkTCPClose:          tcpClose,
		TforkFullMemcopy:       request.FullMemcopy,
		TforkNetworkLock:       request.NetworkLock,
		TforkInjectFiles:       request.InjectFiles,
		TforkInjectSourceFiles: request.InjectSourceFiles,
	}
	options.CreateOpts.Name = request.Name
	options.CreateOpts.IsClone = true

	report, err := containerEngine.ContainerClone(r.Context(), options)
	if err != nil {
		if errors.Is(err, define.ErrNoSuchCtr) {
			utils.ContainerNotFound(w, options.ID, err)
			return
		}
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusCreated, report)
}
