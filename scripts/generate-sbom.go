//go:build ignore

// Command generate-sbom emits a CycloneDX 1.5 inventory from the exact Go
// build information embedded in a release binary.
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Hashes  []hash `json:"hashes,omitempty"`
}
type tools struct {
	Components []component `json:"components"`
}
type metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     tools     `json:"tools"`
	Component component `json:"component"`
}
type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: generate-sbom BINARY VERSION OUTPUT")
		os.Exit(64)
	}
	binary, version, output := os.Args[1], os.Args[2], os.Args[3]
	data, err := os.ReadFile(binary)
	if err != nil {
		fatal(err)
	}
	fileInfo, err := buildinfo.ReadFile(binary)
	if err != nil {
		fatal(err)
	}
	digest := sha256.Sum256(data)
	app := component{Type: "application", Name: "sphinx", Version: version, PURL: "pkg:golang/github.com/marksisson/sphinx@" + version, Hashes: []hash{{Alg: "SHA-256", Content: hex.EncodeToString(digest[:])}}}
	components := make([]component, 0, len(fileInfo.Deps))
	for _, dependency := range fileInfo.Deps {
		path, dependencyVersion := dependency.Path, dependency.Version
		if dependency.Replace != nil {
			path, dependencyVersion = dependency.Replace.Path, dependency.Replace.Version
		}
		components = append(components, component{Type: "library", Name: path, Version: dependencyVersion, PURL: "pkg:golang/" + strings.ReplaceAll(path, "%", "%25") + "@" + dependencyVersion})
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	serial := hex.EncodeToString(digest[:16])
	serial = fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", serial[:8], serial[8:12], serial[12:16], serial[16:20], serial[20:32])
	document := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: serial, Version: 1, Metadata: metadata{Timestamp: time.Now().UTC().Format(time.RFC3339), Tools: tools{Components: []component{{Type: "application", Name: "sphinx-generate-sbom", Version: "1"}}}, Component: app}, Components: components}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(output, encoded, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "generate SBOM:", err)
	os.Exit(1)
}
