package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/marksisson/sphinx/internal/audit"
	"github.com/marksisson/sphinx/internal/identity"
	"github.com/marksisson/sphinx/internal/policy"
	"github.com/marksisson/sphinx/internal/relic"
	"github.com/marksisson/sphinx/internal/schema"
)

const maxDocumentSize = 1 << 20

var pathSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type ValueDecrypter interface {
	Plain(context.Context, []byte) ([]byte, error)
}

type Server struct {
	root      string
	policy    *policy.Policy
	identity  identity.Resolver
	decrypter ValueDecrypter
	audit     *audit.Logger
	logger    *slog.Logger
}

func New(
	root string,
	accessPolicy *policy.Policy,
	resolver identity.Resolver,
	decrypter ValueDecrypter,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) (*Server, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve secrets root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve secrets root symlinks: %w", err)
	}
	return &Server{
		root: resolvedRoot, policy: accessPolicy, identity: resolver,
		decrypter: decrypter, audit: auditLogger, logger: logger,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/relics/{path...}", s.revealRelic)
	return securityHeaders(mux)
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) revealRelic(writer http.ResponseWriter, request *http.Request) {
	requestID := newRequestID()
	secretPath := request.PathValue("path")
	field := request.URL.Query().Get("field")
	event := audit.Event{Time: time.Now().UTC(), RequestID: requestID, Path: secretPath, Facet: field}

	principal, err := s.identity.Resolve(request.Context(), request.RemoteAddr)
	if err != nil {
		event.Reason = "identity verification failed"
		s.record(event)
		s.logger.Warn("Relic petition denied", "request_id", requestID, "reason", event.Reason)
		writeError(writer, http.StatusUnauthorized, requestID, "identity verification failed")
		return
	}
	event.Login, event.Node, event.Tags = principal.Login, principal.Node, principal.Tags

	if err := ValidatePath(secretPath); err != nil {
		event.Reason = "invalid secret path"
		s.record(event)
		writeError(writer, http.StatusBadRequest, requestID, "invalid secret path")
		return
	}

	allowed, reason := s.policy.Authorize(principal, secretPath)
	event.Allowed, event.Reason = allowed, reason
	if !allowed {
		s.record(event)
		s.logger.Warn("Relic petition denied", "request_id", requestID, "login", principal.Login, "path", secretPath)
		writeError(writer, http.StatusForbidden, requestID, "access denied")
		return
	}
	if err := s.audit.Record(event); err != nil {
		s.logger.Error("audit write failed", "request_id", requestID, "error", err)
		writeError(writer, http.StatusInternalServerError, requestID, "audit unavailable")
		return
	}

	filename, err := s.relicFilename(secretPath)
	if err != nil {
		s.logger.Error("resolve Relic file", "request_id", requestID, "error", err)
		writeError(writer, http.StatusNotFound, requestID, "Relic not found")
		return
	}
	encrypted, err := readLimited(filename, maxDocumentSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(writer, http.StatusNotFound, requestID, "Relic not found")
		} else {
			s.logger.Error("read sealed Relic", "request_id", requestID, "error", err)
			writeError(writer, http.StatusInternalServerError, requestID, "Relic unavailable")
		}
		return
	}
	defer clear(encrypted)

	plaintext, err := s.decrypter.Plain(request.Context(), encrypted)
	if err != nil {
		s.logger.Error("unseal Relic", "request_id", requestID, "error", err)
		writeError(writer, http.StatusInternalServerError, requestID, "Relic unavailable")
		return
	}
	defer clear(plaintext)
	document, err := relic.ParsePlain(plaintext)
	if err != nil {
		s.logger.Error("parse Relic", "request_id", requestID, "error", err)
		writeError(writer, http.StatusInternalServerError, requestID, "Relic unavailable")
		return
	}
	definition, err := schema.Load(s.root, document.Schema)
	if err == nil {
		err = definition.ValidateDocument(document.Essence, document.Inscription)
	}
	if err != nil {
		s.logger.Error("validate Relic schema", "request_id", requestID, "error", err)
		writeError(writer, http.StatusInternalServerError, requestID, "Relic unavailable")
		return
	}
	var value any = document.Essence
	if field != "" {
		selected, ok := document.Essence[field]
		if !ok {
			writeError(writer, http.StatusNotFound, requestID, "Essence facet not found")
			return
		}
		value = selected
	}
	writeJSON(writer, http.StatusOK, map[string]any{"essence": value})
}

func (s *Server) relicFilename(secretPath string) (string, error) {
	filename := filepath.Join(append([]string{s.root}, append(strings.Split(secretPath, "/"), "relic.yaml")...)...)
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(s.root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("secret path escapes root")
	}
	return resolved, nil
}

func (s *Server) record(event audit.Event) {
	if err := s.audit.Record(event); err != nil {
		s.logger.Error("audit write failed", "request_id", event.RequestID, "error", err)
	}
}

func ValidatePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return fmt.Errorf("path is empty or absolute")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || !pathSegment.MatchString(segment) {
			return fmt.Errorf("invalid path segment")
		}
	}
	return nil
}

func readLimited(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("encrypted document exceeds %d bytes", limit)
	}
	return data, nil
}

func newRequestID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, requestID, message string) {
	writeJSON(writer, status, map[string]string{"error": message, "request_id": requestID})
}
