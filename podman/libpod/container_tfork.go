//go:build !remote

package libpod

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type TforkDumpState string

const (
	TforkDumpStateNone     TforkDumpState = "none"
	TforkDumpStateInflight TforkDumpState = "inflight"
	TforkDumpStateDone     TforkDumpState = "done"
)

func (c *Container) TforkDumpStatus() (TforkDumpState, error) {
	if c.config.TforkImgDir == "" {
		return TforkDumpStateNone, nil
	}
	if c.config.TforkPersistent == "" {
		return TforkDumpStateNone, nil
	}
	donePath := filepath.Join(c.config.TforkImgDir, ".dump.done")
	if _, err := os.Stat(donePath); err == nil {
		return TforkDumpStateDone, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s: %w", donePath, err)
	}
	inflightPath := filepath.Join(c.config.TforkImgDir, ".dump.inflight")
	if _, err := os.Stat(inflightPath); err == nil {
		return TforkDumpStateInflight, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s: %w", inflightPath, err)
	}
	return TforkDumpStateInflight, nil
}

func (c *Container) TforkWaitDumpDone(timeout time.Duration) (TforkDumpState, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := c.TforkDumpStatus()
		if err != nil {
			return st, err
		}
		if st == TforkDumpStateDone || st == TforkDumpStateNone {
			return st, nil
		}
		if !time.Now().Before(deadline) {
			return st, fmt.Errorf("tfork dump still %s after %s", st, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (r *Runtime) FindLatestDoneTforkChild(sourceID string) (*Container, error) {
	all, err := r.GetAllContainers()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	var best *Container
	for _, c := range all {
		if c.config.TforkSourceID != sourceID {
			continue
		}
		if c.config.TforkPersistent == "" {
			continue
		}
		st, err := c.TforkDumpStatus()
		if err != nil || st != TforkDumpStateDone {
			continue
		}
		if best == nil || c.config.CreatedTime.After(best.config.CreatedTime) {
			best = c
		}
	}
	return best, nil
}

func (c *Container) TforkImgDir() string {
	return c.config.TforkImgDir
}

func (c *Container) TforkParentClone() string {
	return c.config.TforkParentClone
}

func (c *Container) TforkSourceID() string {
	return c.config.TforkSourceID
}

func (c *Container) TforkPersistent() string {
	return c.config.TforkPersistent
}

func (c *Container) TforkDumpdHolderPid() int {
	return c.config.TforkDumpdHolderPid
}

func ReadProcStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	rp := strings.LastIndexByte(string(data), ')')
	if rp < 0 || rp+2 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[rp+2:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat: only %d post-comm fields", pid, len(fields))
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func (c *Container) TforkChainAncestors() ([]*Container, error) {
	const maxDepth = 64
	var chain []*Container
	cur := c
	for i := 0; i < maxDepth; i++ {
		if cur.config.TforkParentClone == "" {
			return chain, nil
		}
		parent, err := c.runtime.LookupContainer(cur.config.TforkParentClone)
		if err != nil {
			return chain, fmt.Errorf("lookup parent %s: %w", cur.config.TforkParentClone, err)
		}
		chain = append(chain, parent)
		cur = parent
	}
	return chain, fmt.Errorf("tfork chain depth exceeds %d (cycle?)", maxDepth)
}
