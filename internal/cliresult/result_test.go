package cliresult

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestStableClassifications(t *testing.T) {
	tests := map[string]struct {
		message, code string
		exit          int
	}{"usage": {"unknown flag --listen-address", "usage", EXUsage}, "data": {"invalid artifact yaml", "data_invalid", EXDataErr}, "missing": {"schema does not exist", "not_found", EXNoInput}, "tailscale": {"tailscaled is not authenticated", "tailscale_unavailable", EXUnavailable}, "integrity": {"decree signature verification failed", "integrity_failed", EXDataErr}, "authorization": {"current seeker is not authorized", "authorization_denied", EXNoPerm}, "guardian": {"no configured guardian recipient intersects", "guardian_unavailable", EXNoPerm}, "recovery": {"incomplete transaction; recovery required", "recovery_required", EXTempFail}, "config": {"configuration is unsafe", "config_invalid", EXConfig}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := Classify(errors.New(test.message))
			if got.Code != test.code || got.Exit != test.exit {
				t.Fatalf("classification=%#v", got)
			}
		})
	}
}
func TestSingleObjectEnvelopes(t *testing.T) {
	var output bytes.Buffer
	if err := WriteSuccess(&output, map[string]any{"value": 1}, nil); err != nil {
		t.Fatal(err)
	}
	var success map[string]any
	if err := json.Unmarshal(output.Bytes(), &success); err != nil {
		t.Fatal(err)
	}
	if success["version"] != float64(1) || success["ok"] != true {
		t.Fatalf("success=%s", output.String())
	}
	output.Reset()
	exit, err := WriteError(&output, Usage(errors.New("bad argument")))
	if err != nil || exit != EXUsage {
		t.Fatalf("exit=%d err=%v", exit, err)
	}
	var failed map[string]any
	if err := json.Unmarshal(output.Bytes(), &failed); err != nil {
		t.Fatal(err)
	}
	if failed["ok"] != false {
		t.Fatalf("failure=%s", output.String())
	}
}
