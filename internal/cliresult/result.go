// Package cliresult defines the stable command error and JSON-envelope contract.
package cliresult

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const Version = 1

const (
	EXUsage       = 64
	EXDataErr     = 65
	EXNoInput     = 66
	EXUnavailable = 69
	EXSoftware    = 70
	EXCantCreate  = 73
	EXIOErr       = 74
	EXTempFail    = 75
	EXNoPerm      = 77
	EXConfig      = 78
)

type Failure struct {
	Code      string
	Message   string
	Exit      int
	Retryable bool
	Cause     error
}

func (e *Failure) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Code
}
func (e *Failure) Unwrap() error { return e.Cause }
func New(code, message string, exit int, retryable bool, cause error) error {
	return &Failure{Code: code, Message: message, Exit: exit, Retryable: retryable, Cause: cause}
}

type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type successEnvelope struct {
	Version  int       `json:"version"`
	OK       bool      `json:"ok"`
	Data     any       `json:"data"`
	Warnings []Warning `json:"warnings"`
}
type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type errorEnvelope struct {
	Version int       `json:"version"`
	OK      bool      `json:"ok"`
	Error   errorBody `json:"error"`
}

func WriteSuccess(w io.Writer, data any, warnings []Warning) error {
	if data == nil {
		data = struct{}{}
	}
	if warnings == nil {
		warnings = []Warning{}
	}
	return json.NewEncoder(w).Encode(successEnvelope{Version: Version, OK: true, Data: data, Warnings: warnings})
}
func WriteError(w io.Writer, err error) (int, error) {
	failure := Classify(err)
	writeErr := json.NewEncoder(w).Encode(errorEnvelope{Version: Version, OK: false, Error: errorBody{Code: failure.Code, Message: failure.Error(), Retryable: failure.Retryable}})
	return failure.Exit, writeErr
}

func Classify(err error) *Failure {
	if err == nil {
		return &Failure{Code: "internal_error", Message: "missing command error", Exit: EXSoftware}
	}
	var known *Failure
	if errors.As(err, &known) {
		return known
	}
	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "unknown command"), strings.Contains(lower, "unknown flag"), strings.Contains(lower, "requires at least"), strings.Contains(lower, "requires exactly"), strings.Contains(lower, "required flag"), strings.Contains(lower, "accepts "), strings.Contains(lower, "arg(s)"), strings.Contains(lower, "tomb reference must"), strings.Contains(lower, "chamber path"), strings.Contains(lower, "guardian name"), strings.Contains(lower, "provider is read-only"):
		return &Failure{Code: "usage", Message: message, Exit: EXUsage, Cause: err}
	case errors.Is(err, os.ErrNotExist), strings.Contains(lower, "does not exist"), strings.Contains(lower, "is missing"), strings.Contains(lower, "has no exact chamber"), strings.Contains(lower, "not found"):
		return &Failure{Code: "not_found", Message: message, Exit: EXNoInput, Cause: err}
	case strings.Contains(lower, "tailscale"):
		return &Failure{Code: "tailscale_unavailable", Message: message, Exit: EXUnavailable, Cause: err}
	case strings.Contains(lower, "proclamation verification failed"), strings.Contains(lower, "proclamation signing identity does not match"):
		return &Failure{Code: "proclamation_rejected", Message: message, Exit: EXNoPerm, Cause: err}
	case strings.Contains(lower, "no configured guardian"), strings.Contains(lower, "no eligible configured guardian"), strings.Contains(lower, "guardian recipient intersects"), strings.Contains(lower, "unwrap the artifact"):
		return &Failure{Code: "guardian_unavailable", Message: message, Exit: EXNoPerm, Cause: err}
	case strings.Contains(lower, "keychain"), strings.Contains(lower, "provider is unavailable"), strings.Contains(lower, "provider operation is unsupported"), strings.Contains(lower, "materialize tomb"), strings.Contains(lower, "git ls-remote"):
		return &Failure{Code: "dependency_unavailable", Message: message, Exit: EXUnavailable, Cause: err}
	case strings.Contains(lower, "not authorized"):
		return &Failure{Code: "authorization_denied", Message: message, Exit: EXNoPerm, Cause: err}
	case strings.Contains(lower, "signature"), strings.Contains(lower, "mac"), strings.Contains(lower, "digest"), strings.Contains(lower, "signed lock"):
		return &Failure{Code: "integrity_failed", Message: message, Exit: EXDataErr, Cause: err}
	case strings.Contains(lower, "controlling terminal"), strings.Contains(lower, "terminal input"), strings.Contains(lower, "write command output"), strings.Contains(lower, "stdout pipe"):
		return &Failure{Code: "io_error", Message: message, Exit: EXIOErr, Cause: err}
	case strings.Contains(lower, "cannot create"), strings.Contains(lower, "create tomb cache directory"), strings.Contains(lower, "create transaction"):
		return &Failure{Code: "cannot_create", Message: message, Exit: EXCantCreate, Cause: err}
	case strings.Contains(lower, "incomplete transaction"), strings.Contains(lower, "recovery required"):
		return &Failure{Code: "recovery_required", Message: message, Exit: EXTempFail, Retryable: true, Cause: err}
	case strings.Contains(lower, "worktree"), strings.Contains(lower, "journal"), strings.Contains(lower, "concurrent"), strings.Contains(lower, "transaction"):
		return &Failure{Code: "worktree_conflict", Message: message, Exit: EXTempFail, Retryable: true, Cause: err}
	case strings.Contains(lower, "configuration"), strings.Contains(lower, "config"), strings.Contains(lower, "tomb alias"):
		return &Failure{Code: "config_invalid", Message: message, Exit: EXConfig, Cause: err}
	case strings.Contains(lower, "yaml"), strings.Contains(lower, "schema"), strings.Contains(lower, "artifact"), strings.Contains(lower, "decree"), strings.Contains(lower, "signature"), strings.Contains(lower, "digest"), strings.Contains(lower, "sops"), strings.Contains(lower, "recipient"):
		return &Failure{Code: "data_invalid", Message: message, Exit: EXDataErr, Cause: err}
	default:
		return &Failure{Code: "internal_error", Message: message, Exit: EXSoftware, Cause: err}
	}
}
func Usage(err error) error { return New("usage", err.Error(), EXUsage, false, err) }
func Declined(message string) error {
	return New("confirmation_declined", message, EXNoPerm, false, nil)
}
func IO(action string, err error) error {
	return New("io_error", fmt.Sprintf("%s: %v", action, err), EXIOErr, false, err)
}
