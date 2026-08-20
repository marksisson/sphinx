package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/marksisson/sphinx/internal/relic"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/secret"
	"github.com/marksisson/sphinx/internal/tomb"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type authorOptions struct {
	tomb     string
	schema   string
	stdin    bool
	fromJSON string
	key      keyOptions
}

type revealOptions struct {
	server   string
	tomb     string
	facet    string
	recovery bool
}

type suppliedValues struct {
	Essence     map[string]any `json:"essence"`
	Inscription map[string]any `json:"inscription"`
}

func newRelicCommand() *cobra.Command {
	command := &cobra.Command{Use: "relic", Short: "Create, inspect, update, and reveal Relics"}
	command.AddCommand(
		newEntombCommand(), newInspectCommand(), newRevealCommand(), newInscribeCommand(), newResealCommand(),
	)
	return command
}

func newEntombCommand() *cobra.Command {
	var options authorOptions
	command := &cobra.Command{
		Use:   "entomb PATH",
		Short: "Create and encrypt a new Relic",
		Long: `Create a new Relic from a Tomb schema. Essence fields are prompted
without terminal echo. The recovery passphrase is supplied securely and is
never generated or stored by Sphinx.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEntomb(options, args[0])
		},
	}
	addAuthorFlags(command, &options, true)
	registerSchemaCompletion(command, &options)
	return command
}

func newResealCommand() *cobra.Command {
	var options authorOptions
	command := &cobra.Command{
		Use:   "reseal PATH",
		Short: "Replace and re-encrypt a Relic's Essence",
		Long: `Replace the structured Essence of an existing Relic. Resealing
rotates the SOPS data key and requires the existing recovery passphrase.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runReseal(options, args[0])
		},
	}
	addAuthorFlags(command, &options, false)
	registerPathCompletion(command, &options.tomb)
	return command
}

func newInscribeCommand() *cobra.Command {
	options := authorOptions{tomb: "./secrets"}
	command := &cobra.Command{
		Use:   "inscribe PATH",
		Short: "Update a Relic's non-secret Inscription",
		Long: `Update repository-visible metadata defined by the Relic's schema.
Sphinx uses its online Keychain identity to recompute the SOPS integrity MAC;
the recovery passphrase is not required.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runInscribe(options, args[0])
		},
	}
	command.Flags().StringVar(&options.tomb, "tomb", options.tomb, "local Tomb root")
	addKeyFlags(command, &options.key)
	registerPathCompletion(command, &options.tomb)
	return command
}

func newInspectCommand() *cobra.Command {
	var tombRoot string
	var key keyOptions
	command := &cobra.Command{
		Use:   "inspect PATH",
		Short: "Show a Relic's schema and non-secret Inscription",
		Long:  "Verify the SOPS MAC, then show only the schema and non-secret Inscription.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			encrypted, err := relic.Read(tombRoot, args[0])
			if err != nil {
				return err
			}
			identity, recipient, err := onlineIdentity(key)
			if err != nil {
				return err
			}
			configuration, err := tomb.LoadConfiguration(tombRoot)
			if err != nil {
				return fmt.Errorf("load Tomb configuration: %w", err)
			}
			if configuration.OnlineRecipient != recipient {
				return fmt.Errorf("Keychain identity does not match the Tomb's online recipient")
			}
			if configuration.Recovery.Type != secret.RecoveryType {
				return fmt.Errorf("unsupported Tomb recovery type %q", configuration.Recovery.Type)
			}
			decrypter, err := secret.NewDecrypter(identity)
			if err != nil {
				return err
			}
			plaintext, err := decrypter.Plain(context.Background(), encrypted)
			if err != nil {
				return err
			}
			defer clear(plaintext)
			document, err := relic.ParsePlain(plaintext)
			if err != nil {
				return err
			}
			definition, err := schema.Load(tombRoot, document.Schema)
			if err != nil {
				return err
			}
			if err := definition.ValidateDocument(document.Essence, document.Inscription); err != nil {
				return err
			}
			output := map[string]any{"path": args[0], "format": document.Format, "schema": document.Schema, "inscription": document.Inscription}
			formatted, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(formatted))
			return nil
		},
	}
	command.Flags().StringVar(&tombRoot, "tomb", "./secrets", "local Tomb root")
	addKeyFlags(command, &key)
	registerPathCompletion(command, &tombRoot)
	return command
}

func newRevealCommand() *cobra.Command {
	options := revealOptions{server: "http://127.0.0.1:8787", tomb: "./secrets"}
	command := &cobra.Command{
		Use:   "reveal PATH",
		Short: "Reveal a Relic's Essence",
		Long: `Request an authorized Essence from the Sphinx daemon. With
--recovery, bypass the daemon and decrypt a local Tomb using the recovery
passphrase supplied through a terminal with echo disabled.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if options.recovery {
				return revealRecovery(options, args[0])
			}
			return revealOnline(options, args[0])
		},
	}
	command.Flags().StringVar(&options.server, "server", options.server, "Sphinx base URL")
	command.Flags().StringVar(&options.tomb, "tomb", options.tomb, "local Tomb root used with --recovery")
	command.Flags().StringVar(&options.facet, "facet", "", "reveal one field (facet) of the Essence")
	command.Flags().BoolVar(&options.recovery, "recovery", false, "decrypt locally using the recovery passphrase")
	registerPathCompletion(command, &options.tomb)
	_ = command.RegisterFlagCompletionFunc("facet", func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return facetNames(options.tomb, args[0]), cobra.ShellCompDirectiveNoFileComp
	})
	return command
}

func addAuthorFlags(command *cobra.Command, options *authorOptions, includeSchema bool) {
	options.tomb = "./secrets"
	command.Flags().StringVar(&options.tomb, "tomb", options.tomb, "local Tomb root")
	if includeSchema {
		command.Flags().StringVar(&options.schema, "schema", "", "Relic schema reference (required)")
		_ = command.MarkFlagRequired("schema")
	}
	command.Flags().BoolVar(&options.stdin, "stdin", false, "read Essence and Inscription as JSON from stdin")
	command.Flags().StringVar(&options.fromJSON, "from-json", "", "read Essence and Inscription from a JSON file")
	command.MarkFlagsMutuallyExclusive("stdin", "from-json")
	addKeyFlags(command, &options.key)
}

func runEntomb(options authorOptions, relicPath string) error {
	filename, err := relic.Filename(options.tomb, relicPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("Relic %q already exists; use reseal", relicPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	definition, err := schema.Load(options.tomb, options.schema)
	if err != nil {
		return err
	}
	values, err := collectValues(*definition, suppliedValues{}, options, false)
	if err != nil {
		return err
	}
	if err := definition.ValidateDocument(values.Essence, values.Inscription); err != nil {
		return err
	}
	passphrase, err := readPassphrase("Recovery passphrase: ", true)
	if err != nil {
		return err
	}
	_, recipient, err := onlineIdentity(options.key)
	if err != nil {
		return err
	}
	if err := ensureTombConfiguration(options.tomb, recipient, passphrase, true); err != nil {
		return err
	}
	document := relic.Document{Format: relic.FormatVersion, Schema: definition.Reference(), Essence: values.Essence, Inscription: values.Inscription}
	plaintext, err := relic.MarshalPlain(document)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encrypted, err := secret.Encrypt(plaintext, recipient, passphrase)
	if err != nil {
		return err
	}
	if err := relic.WriteAtomic(options.tomb, relicPath, encrypted); err != nil {
		return err
	}
	fmt.Printf("Entombed %s\n", relicPath)
	return nil
}

func runReseal(options authorOptions, relicPath string) error {
	encrypted, err := relic.Read(options.tomb, relicPath)
	if err != nil {
		return err
	}
	identity, recipient, err := onlineIdentity(options.key)
	if err != nil {
		return err
	}
	decrypter, err := secret.NewDecrypter(identity)
	if err != nil {
		return err
	}
	plaintext, err := decrypter.Plain(context.Background(), encrypted)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	document, err := relic.ParsePlain(plaintext)
	if err != nil {
		return err
	}
	definition, err := schema.Load(options.tomb, document.Schema)
	if err != nil {
		return err
	}
	values, err := collectValues(*definition, suppliedValues{Essence: document.Essence, Inscription: document.Inscription}, options, true)
	if err != nil {
		return err
	}
	if err := definition.ValidateDocument(values.Essence, values.Inscription); err != nil {
		return err
	}
	passphrase, err := readPassphrase("Recovery passphrase: ", false)
	if err != nil {
		return err
	}
	if err := ensureTombConfiguration(options.tomb, recipient, passphrase, false); err != nil {
		return err
	}
	recovered, err := secret.DecryptRecovery(encrypted, passphrase)
	if err != nil {
		return fmt.Errorf("verify recovery passphrase: %w", err)
	}
	clear(recovered)
	document.Essence = values.Essence
	document.Inscription = values.Inscription
	document.Recovery = nil
	updatedPlain, err := relic.MarshalPlain(*document)
	if err != nil {
		return err
	}
	defer clear(updatedPlain)
	updated, err := secret.Encrypt(updatedPlain, recipient, passphrase)
	if err != nil {
		return err
	}
	if err := relic.WriteAtomic(options.tomb, relicPath, updated); err != nil {
		return err
	}
	fmt.Printf("Resealed %s\n", relicPath)
	return nil
}

func runInscribe(options authorOptions, relicPath string) error {
	encrypted, err := relic.Read(options.tomb, relicPath)
	if err != nil {
		return err
	}
	identity, recipient, err := onlineIdentity(options.key)
	if err != nil {
		return err
	}
	configuration, err := tomb.LoadConfiguration(options.tomb)
	if err != nil {
		return fmt.Errorf("load Tomb configuration: %w", err)
	}
	if configuration.OnlineRecipient != recipient {
		return fmt.Errorf("Keychain identity does not match the Tomb's online recipient")
	}
	decrypter, err := secret.NewDecrypter(identity)
	if err != nil {
		return err
	}
	plaintext, err := decrypter.Plain(context.Background(), encrypted)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	document, err := relic.ParsePlain(plaintext)
	if err != nil {
		return err
	}
	definition, err := schema.Load(options.tomb, document.Schema)
	if err != nil {
		return err
	}
	inscription, err := promptFields(definition.Inscription, document.Inscription, false, true)
	if err != nil {
		return err
	}
	if err := definition.ValidateDocument(document.Essence, inscription); err != nil {
		return err
	}
	document.Inscription = inscription
	updatedPlain, err := relic.MarshalPlain(*document)
	if err != nil {
		return err
	}
	defer clear(updatedPlain)
	updated, err := secret.Update(encrypted, updatedPlain, identity)
	if err != nil {
		return err
	}
	if err := relic.WriteAtomic(options.tomb, relicPath, updated); err != nil {
		return err
	}
	fmt.Printf("Inscribed %s\n", relicPath)
	return nil
}

func collectValues(definition schema.Definition, existing suppliedValues, options authorOptions, keepExisting bool) (suppliedValues, error) {
	if options.stdin || options.fromJSON != "" {
		var reader io.Reader
		if options.stdin {
			reader = io.LimitReader(os.Stdin, 1<<20)
		} else {
			file, err := os.Open(options.fromJSON)
			if err != nil {
				return suppliedValues{}, err
			}
			defer file.Close()
			reader = io.LimitReader(file, 1<<20)
		}
		var values suppliedValues
		decoder := json.NewDecoder(reader)
		decoder.DisallowUnknownFields()
		decoder.UseNumber()
		if err := decoder.Decode(&values); err != nil {
			return suppliedValues{}, fmt.Errorf("decode supplied Relic values: %w", err)
		}
		if values.Essence == nil {
			values.Essence = make(map[string]any)
		}
		if values.Inscription == nil {
			values.Inscription = existing.Inscription
		}
		if err := normalizeJSONNumbers(definition.Essence, values.Essence); err != nil {
			return suppliedValues{}, err
		}
		if err := normalizeJSONNumbers(definition.Inscription, values.Inscription); err != nil {
			return suppliedValues{}, err
		}
		return values, nil
	}
	essence, err := promptFields(definition.Essence, existing.Essence, true, keepExisting)
	if err != nil {
		return suppliedValues{}, err
	}
	inscription := existing.Inscription
	if !keepExisting {
		inscription, err = promptFields(definition.Inscription, existing.Inscription, false, false)
		if err != nil {
			return suppliedValues{}, err
		}
	}
	return suppliedValues{Essence: essence, Inscription: inscription}, nil
}

func normalizeJSONNumbers(fields []schema.Field, values map[string]any) error {
	for _, field := range fields {
		value, ok := values[field.Name]
		if !ok || field.Type != "integer" {
			continue
		}
		number, ok := value.(json.Number)
		if !ok {
			continue
		}
		parsed, err := number.Int64()
		if err != nil {
			return fmt.Errorf("%s: must be an integer", field.Name)
		}
		values[field.Name] = parsed
	}
	return nil
}

func promptFields(fields []schema.Field, existing map[string]any, secure, keepExisting bool) (map[string]any, error) {
	values := make(map[string]any)
	for key, value := range existing {
		values[key] = value
	}
	for _, field := range fields {
		label := field.Label()
		if field.Type == "enum" {
			label += " (" + strings.Join(field.Values, "/") + ")"
		}
		if keepExisting {
			if _, ok := existing[field.Name]; ok {
				label += " [leave blank to keep]"
			}
		}
		var input string
		var err error
		if secure {
			input, err = readSecret(label + ": ")
		} else {
			input, err = readLine(label + ": ")
		}
		if err != nil {
			return nil, err
		}
		if input == "" && keepExisting {
			continue
		}
		if input == "" && !field.Required {
			delete(values, field.Name)
			continue
		}
		value, err := schema.ParseValue(field, input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field.Name, err)
		}
		values[field.Name] = value
	}
	return values, nil
}

func revealRecovery(options revealOptions, relicPath string) error {
	encrypted, err := relic.Read(options.tomb, relicPath)
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase("Recovery passphrase: ", false)
	if err != nil {
		return err
	}
	configuration, err := tomb.LoadConfiguration(options.tomb)
	if err != nil {
		return fmt.Errorf("load Tomb configuration: %w", err)
	}
	if configuration.Recovery.Type != secret.RecoveryType {
		return fmt.Errorf("unsupported Tomb recovery type %q", configuration.Recovery.Type)
	}
	if err := secret.VerifyRecoveryCheck(configuration.Recovery.EncryptedCheck, passphrase); err != nil {
		return fmt.Errorf("verify Tomb recovery passphrase: %w", err)
	}
	if err := secret.ValidateRecipients(encrypted, configuration.OnlineRecipient); err != nil {
		return err
	}
	plaintext, err := secret.DecryptRecovery(encrypted, passphrase)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	document, err := relic.ParsePlain(plaintext)
	if err != nil {
		return err
	}
	definition, err := schema.Load(options.tomb, document.Schema)
	if err != nil {
		return err
	}
	if err := definition.ValidateDocument(document.Essence, document.Inscription); err != nil {
		return err
	}
	return printEssence(document.Essence, options.facet)
}

func revealOnline(options revealOptions, relicPath string) error {
	if err := relic.ValidatePath(relicPath); err != nil {
		return err
	}
	endpoint := strings.TrimRight(options.server, "/") + "/v1/relics/" + relicPath
	if options.facet != "" {
		endpoint += "?field=" + url.QueryEscape(options.facet)
	}
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
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
	var value any
	if err := json.Unmarshal(envelope.Essence, &value); err != nil {
		return err
	}
	return printValue(value)
}

func printEssence(essence map[string]any, facet string) error {
	if facet != "" {
		value, ok := essence[facet]
		if !ok {
			return fmt.Errorf("Essence has no facet %q", facet)
		}
		return printValue(value)
	}
	return printValue(essence)
}

func printValue(value any) error {
	if text, ok := value.(string); ok {
		fmt.Print(text)
		if !strings.HasSuffix(text, "\n") {
			fmt.Println()
		}
		return nil
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

func ensureTombConfiguration(root, recipient, passphrase string, create bool) error {
	configuration, err := tomb.LoadConfiguration(root)
	if os.IsNotExist(err) && create {
		check, checkErr := secret.NewRecoveryCheck(passphrase)
		if checkErr != nil {
			return checkErr
		}
		return tomb.WriteConfiguration(root, tomb.Configuration{
			Format:          1,
			OnlineRecipient: recipient,
			Recovery: tomb.RecoveryConfiguration{
				Type:           secret.RecoveryType,
				EncryptedCheck: check,
			},
		})
	}
	if err != nil {
		return fmt.Errorf("load Tomb configuration: %w", err)
	}
	if configuration.OnlineRecipient != recipient {
		return fmt.Errorf("Keychain identity does not match the Tomb's online recipient")
	}
	if configuration.Recovery.Type != secret.RecoveryType {
		return fmt.Errorf("unsupported Tomb recovery type %q", configuration.Recovery.Type)
	}
	if err := secret.VerifyRecoveryCheck(configuration.Recovery.EncryptedCheck, passphrase); err != nil {
		return fmt.Errorf("verify Tomb recovery passphrase: %w", err)
	}
	return nil
}

func onlineIdentity(options keyOptions) (identity, recipient string, err error) {
	identity, err = keychain.Get(options.service, options.account)
	if err != nil {
		return "", "", fmt.Errorf("load Sphinx identity: %w", err)
	}
	parsed, err := age.ParseX25519Identity(strings.TrimSpace(identity))
	if err != nil {
		return "", "", fmt.Errorf("parse Sphinx identity: %w", err)
	}
	return identity, parsed.Recipient().String(), nil
}

func readPassphrase(prompt string, confirm bool) (string, error) {
	passphrase, err := readSecret(prompt)
	if err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", fmt.Errorf("recovery passphrase cannot be empty")
	}
	if confirm {
		repeated, err := readSecret("Confirm recovery passphrase: ")
		if err != nil {
			return "", err
		}
		if passphrase != repeated {
			return "", fmt.Errorf("recovery passphrases do not match")
		}
	}
	return passphrase, nil
}

func readSecret(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("secure terminal input is required: %w", err)
	}
	defer tty.Close()
	if !term.IsTerminal(int(tty.Fd())) {
		return "", fmt.Errorf("secure terminal input is required")
	}
	fmt.Fprint(tty, prompt)
	value, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	defer clear(value)
	return string(value), nil
}

func readLine(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("terminal input is required: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func registerSchemaCompletion(command *cobra.Command, options *authorOptions) {
	_ = command.RegisterFlagCompletionFunc("schema", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		definitions, err := schema.LoadAll(options.tomb)
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		values := make([]string, 0, len(definitions))
		for _, definition := range definitions {
			values = append(values, definition.Reference()+"\t"+definition.Description)
		}
		sort.Strings(values)
		return values, cobra.ShellCompDirectiveNoFileComp
	})
}

func registerPathCompletion(command *cobra.Command, tombRoot *string) {
	command.ValidArgsFunction = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		paths, err := relic.Paths(*tombRoot)
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		sort.Strings(paths)
		return paths, cobra.ShellCompDirectiveNoFileComp
	}
}

func facetNames(tombRoot, relicPath string) []string {
	data, err := relic.Read(tombRoot, relicPath)
	if err != nil {
		return nil
	}
	header, err := relic.ParseHeader(data)
	if err != nil {
		return nil
	}
	definition, err := schema.Load(tombRoot, header.Schema)
	if err != nil {
		return nil
	}
	values := make([]string, 0, len(definition.Essence))
	for _, field := range definition.Essence {
		values = append(values, field.Name+"\t"+field.Label())
	}
	return values
}
