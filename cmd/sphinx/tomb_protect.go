package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/marksisson/sphinx/internal/audit"
	"github.com/marksisson/sphinx/internal/identity"
	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/marksisson/sphinx/internal/policy"
	"github.com/marksisson/sphinx/internal/secret"
	"github.com/marksisson/sphinx/internal/server"
	"github.com/marksisson/sphinx/internal/tomb"
)

type protectOptions struct {
	listen           string
	tomb             string
	tombRef          string
	tombPath         string
	tombCache        string
	decree           string
	chronicle        string
	guardian         guardianOptions
	expectedRevision string
}

func runProtect(options protectOptions) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	source, err := tomb.ParseLocator(options.tomb)
	if err != nil {
		return err
	}
	materialized, err := source.Materialize(ctx, options.tombCache, options.tombRef, options.tombPath)
	if err != nil {
		return err
	}
	if options.expectedRevision != "" && materialized.Revision != options.expectedRevision {
		return fmt.Errorf("materialized tomb revision %q does not match locked revision %q", materialized.Revision, options.expectedRevision)
	}
	logger.Info("tomb opened", "remote", materialized.Remote, "revision", materialized.Revision)

	encodedPrivateKey, err := keychain.Get(options.guardian.service, options.guardian.account)
	if err != nil {
		return fmt.Errorf("load sphinx private key: %w", err)
	}
	_, publicKey, err := guardianKeyPair(options.guardian)
	if err != nil {
		return err
	}
	configuration, err := tomb.LoadConfiguration(materialized.Root)
	if err != nil {
		return fmt.Errorf("load tomb configuration: %w", err)
	}
	if configuration.PublicKey != publicKey {
		return fmt.Errorf("private key in Keychain does not match the tomb's guardian public key")
	}
	if configuration.Recovery.Type != secret.RecoveryType {
		return fmt.Errorf("unsupported tomb recovery type %q", configuration.Recovery.Type)
	}
	decrypter, err := secret.NewDecrypter(encodedPrivateKey)
	if err != nil {
		return err
	}
	decree, err := policy.Load(options.decree)
	if err != nil {
		return err
	}
	chronicle, err := audit.Open(options.chronicle)
	if err != nil {
		return err
	}
	defer chronicle.Close()

	sphinx, err := server.New(materialized.Root, decree, identity.NewTailscaleResolver(), decrypter, chronicle, logger)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr: options.listen, Handler: sphinx.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	serverError := make(chan error, 1)
	go func() {
		logger.Info("sphinx listening", "address", options.listen)
		serverError <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownContext)
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
