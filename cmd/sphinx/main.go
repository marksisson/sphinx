package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/audit"
	"github.com/marksisson/sphinx/internal/identity"
	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/marksisson/sphinx/internal/policy"
	"github.com/marksisson/sphinx/internal/secret"
	"github.com/marksisson/sphinx/internal/server"
	"github.com/marksisson/sphinx/internal/tomb"
)

const (
	defaultKeychainService = "dev.marksisson.sphinx.age"
	defaultKeychainAccount = "sphinx-v1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "key":
		err = keyCommand(os.Args[2:])
	case "relic":
		err = relicCommand(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func keyCommand(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("usage: sphinx key init|recipient")
	}
	switch arguments[0] {
	case "init":
		return initialize(arguments[1:])
	case "recipient":
		return recipient(arguments[1:])
	default:
		return fmt.Errorf("unknown key command %q", arguments[0])
	}
}

func relicCommand(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("usage: sphinx relic reveal [OPTIONS] PATH")
	}
	if arguments[0] != "reveal" {
		return fmt.Errorf("unknown Relic command %q", arguments[0])
	}
	return reveal(arguments[1:])
}

func initialize(arguments []string) error {
	flags := flag.NewFlagSet("key init", flag.ContinueOnError)
	serviceName, accountName := keychainFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("key init accepts no positional arguments")
	}

	if _, err := keychain.Get(*serviceName, *accountName); err == nil {
		return fmt.Errorf("a Sphinx age identity already exists in Keychain")
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return err
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate age identity: %w", err)
	}
	if err := keychain.Set(*serviceName, *accountName, identity.String()); err != nil {
		return err
	}
	fmt.Println(identity.Recipient().String())
	fmt.Fprintln(os.Stderr, "Sphinx identity stored in macOS Keychain. Create an independent recovery identity before sealing a Tomb.")
	return nil
}

func recipient(arguments []string) error {
	flags := flag.NewFlagSet("key recipient", flag.ContinueOnError)
	serviceName, accountName := keychainFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("key recipient accepts no positional arguments")
	}
	encoded, err := keychain.Get(*serviceName, *accountName)
	if err != nil {
		return err
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("parse Keychain age identity: %w", err)
	}
	fmt.Println(identity.Recipient().String())
	return nil
}

func serve(arguments []string) error {
	cacheDefault, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("resolve user cache directory: %w", err)
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8787", "HTTP listen address")
	tombLocation := flags.String("tomb", "./secrets", "local path, github:OWNER/REPO, or git+URL")
	tombReference := flags.String("tomb-ref", "", "Git branch, tag, or commit; defaults to remote HEAD")
	tombPath := flags.String("tomb-path", ".", "relative Relic root within the Tomb repository")
	tombCache := flags.String("tomb-cache", filepath.Join(cacheDefault, "sphinx", "tombs"), "Git Tomb checkout cache")
	decreeFile := flags.String("decree", "./decree.yaml", "authorization Decree")
	chronicleFile := flags.String("chronicle", "./sphinx-chronicle.jsonl", "Chronicle JSONL file")
	serviceName, accountName := keychainFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("serve accepts no positional arguments")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	tombSource, err := tomb.Parse(*tombLocation)
	if err != nil {
		return err
	}
	materialized, err := tombSource.Materialize(ctx, *tombCache, *tombReference, *tombPath)
	if err != nil {
		return err
	}
	logger.Info("Tomb opened", "remote", materialized.Remote, "revision", materialized.Revision)

	encodedIdentity, err := keychain.Get(*serviceName, *accountName)
	if err != nil {
		return fmt.Errorf("load Sphinx identity: %w", err)
	}
	decrypter, err := secret.NewDecrypter(encodedIdentity)
	if err != nil {
		return err
	}
	decree, err := policy.Load(*decreeFile)
	if err != nil {
		return err
	}
	chronicle, err := audit.Open(*chronicleFile)
	if err != nil {
		return err
	}
	defer chronicle.Close()

	sphinx, err := server.New(
		materialized.Root, decree, identity.NewTailscaleResolver(), decrypter, chronicle, logger,
	)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           sphinx.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverError := make(chan error, 1)
	go func() {
		logger.Info("Sphinx listening", "address", *listen)
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

func reveal(arguments []string) error {
	flags := flag.NewFlagSet("relic reveal", flag.ContinueOnError)
	serverURL := flags.String("server", "http://127.0.0.1:8787", "Sphinx base URL")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: sphinx relic reveal [--server URL] PATH")
	}
	relicPath := flags.Arg(0)
	if err := server.ValidatePath(relicPath); err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(*serverURL, "/")+"/v1/relics/"+relicPath, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		return fmt.Errorf("petition Sphinx: %w", err)
	}
	defer response.Body.Close()

	var envelope struct {
		Essence json.RawMessage `json:"essence"`
		Error   string          `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode Sphinx response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		if envelope.Error == "" {
			envelope.Error = response.Status
		}
		return errors.New(envelope.Error)
	}

	var text string
	if json.Unmarshal(envelope.Essence, &text) == nil {
		fmt.Print(text)
		if !strings.HasSuffix(text, "\n") {
			fmt.Println()
		}
		return nil
	}
	var lines []string
	if json.Unmarshal(envelope.Essence, &lines) == nil {
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	}
	var value any
	if err := json.Unmarshal(envelope.Essence, &value); err != nil {
		return fmt.Errorf("decode Essence: %w", err)
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

func keychainFlags(flags *flag.FlagSet) (*string, *string) {
	serviceName := flags.String("keychain-service", defaultKeychainService, "Keychain service name")
	accountName := flags.String("keychain-account", defaultKeychainAccount, "Keychain account name")
	return serviceName, accountName
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: sphinx COMMAND [OPTIONS]

Commands:
  key init       Generate an age identity and store it in macOS Keychain
  key recipient  Print Sphinx's public age recipient
  serve          Guard a local or Git-hosted Tomb
  relic reveal   Request a Relic's Essence from Sphinx`)
}
