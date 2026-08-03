package abi

import "testing"

func TestTforkSourceSyncModeFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    tforkSourceSyncMode
		wantErr bool
	}{
		{name: "default", value: "", want: tforkSourceSyncFS},
		{name: "syncfs", value: "syncfs", want: tforkSourceSyncFS},
		{name: "case and whitespace", value: " Global\n", want: tforkSourceSyncGlobal},
		{name: "none", value: "none", want: tforkSourceSyncNone},
		{name: "invalid", value: "source", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PODMAN_TFORK_SYNC_MODE", test.value)
			got, err := tforkSourceSyncModeFromEnv()
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got mode %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("mode = %q, want %q", got, test.want)
			}
		})
	}
}
