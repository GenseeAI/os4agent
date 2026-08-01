//go:build !remote && linux

package libpod

import (
	"os"
	"testing"
)

func TestCheckConmonRunningExternalClonePIDIdentity(t *testing.T) {
	pid := os.Getpid()
	startTime, err := ReadProcStartTime(pid)
	if err != nil {
		t.Fatalf("reading test process start time: %v", err)
	}

	ctr := &Container{
		config: &ContainerConfig{
			ExternalSetup:         true,
			TforkInitPIDStartTime: startTime,
		},
		state: &ContainerState{PID: pid},
	}
	runtime := &ConmonOCIRuntime{}

	alive, err := runtime.CheckConmonRunning(ctr)
	if err != nil {
		t.Fatalf("checking matching process identity: %v", err)
	}
	if !alive {
		t.Fatal("matching process identity reported dead")
	}

	ctr.config.TforkInitPIDStartTime++
	alive, err = runtime.CheckConmonRunning(ctr)
	if err != nil {
		t.Fatalf("checking recycled process identity: %v", err)
	}
	if alive {
		t.Fatal("mismatched process identity reported alive")
	}
}
