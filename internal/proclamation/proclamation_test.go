package proclamation

import (
	"errors"
	"fmt"
	"testing"
)

func TestCredentialRedactsFormattingAndCanBeDestroyed(t *testing.T) {
	input := []byte("ten word test proclamation")
	credential := NewCredential(input)
	input[0] = 'X'
	if got := fmt.Sprint(credential); got != "[REDACTED]" {
		t.Fatalf("formatted Credential = %q", got)
	}
	if got := fmt.Sprintf("%#v", credential); got != "[REDACTED]" {
		t.Fatalf("Go-syntax Credential = %q", got)
	}
	want := errors.New("stop")
	if err := credential.WithBytes(func(value []byte) error {
		if string(value) != "ten word test proclamation" {
			t.Fatalf("callback received %q", value)
		}
		value[0] = 'X'
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("WithBytes error = %v", err)
	}
	credential.Destroy()
	if err := credential.WithBytes(func(value []byte) error {
		if len(value) != 0 {
			t.Fatal("destroyed credential retained bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
