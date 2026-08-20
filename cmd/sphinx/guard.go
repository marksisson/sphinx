package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marksisson/sphinx/internal/audit"
	"github.com/marksisson/sphinx/internal/identity"
	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/marksisson/sphinx/internal/policy"
	"github.com/marksisson/sphinx/internal/secret"
	"github.com/marksisson/sphinx/internal/server"
	"github.com/marksisson/sphinx/internal/tomb"
	"github.com/spf13/cobra"
)

type guardOptions struct {
	listen        string
	tomb          string
	tombReference string
	tombPath      string
	tombCache     string
	decree        string
	chronicle     string
	key           keyOptions
}

func newGuardCommand() *cobra.Command {
	cache, _ := os.UserCacheDir()
	options := guardOptions{tombCache: filepath.Join(cache, "sphinx", "tombs")}
	command := &cobra.Command{
		Use:   "guard",
		Short: "Run the Sphinx daemon to guard a Tomb",
		Long: `Run the Sphinx daemon to guard a local or Git-hosted Tomb.

The daemon authenticates Petitions through Tailscale, evaluates Decrees,
unseals authorized Relics, and records Judgments in the Chronicle.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGuard(options)
		},
	}
	command.Flags().StringVar(&options.listen, "listen", "127.0.0.1:8787", "HTTP listen address")
	command.Flags().StringVar(&options.tomb, "tomb", "./secrets", "local path, github:OWNER/REPO, or git+URL")
	command.Flags().StringVar(&options.tombReference, "tomb-ref", "", "Git branch, tag, or commit; defaults to remote HEAD")
	command.Flags().StringVar(&options.tombPath, "tomb-path", ".", "relative Relic root within the Tomb")
	command.Flags().StringVar(&options.tombCache, "tomb-cache", options.tombCache, "Git Tomb checkout cache")
	command.Flags().StringVar(&options.decree, "decree", "./decree.yaml", "authorization Decree")
	command.Flags().StringVar(&options.chronicle, "chronicle", "./sphinx-chronicle.jsonl", "Chronicle JSONL file")
	addKeyFlags(command, &options.key)
	return command
}

func runGuard(options guardOptions) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	source, err := tomb.Parse(options.tomb)
	if err != nil {
		return err
	}
	materialized, err := source.Materialize(ctx, options.tombCache, options.tombReference, options.tombPath)
	if err != nil {
		return err
	}
	logger.Info("Tomb opened", "remote", materialized.Remote, "revision", materialized.Revision)

	encodedIdentity, err := keychain.Get(options.key.service, options.key.account)
	if err != nil {
		return fmt.Errorf("load Sphinx identity: %w", err)
	}
	_, onlineRecipient, err := onlineIdentity(options.key)
	if err != nil {
		return err
	}
	configuration, err := tomb.LoadConfiguration(materialized.Root)
	if err != nil {
		return fmt.Errorf("load Tomb configuration: %w", err)
	}
	if configuration.OnlineRecipient != onlineRecipient {
		return fmt.Errorf("Keychain identity does not match the Tomb's online recipient")
	}
	if configuration.Recovery.Type != secret.RecoveryType {
		return fmt.Errorf("unsupported Tomb recovery type %q", configuration.Recovery.Type)
	}
	decrypter, err := secret.NewDecrypter(encodedIdentity)
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
		logger.Info("Sphinx listening", "address", options.listen)
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
