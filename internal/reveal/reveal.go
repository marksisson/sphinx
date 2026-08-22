// Package reveal coordinates the synchronous fail-closed reveal flow. It has
// no network-service, offline, or identity-cache abstraction.
package reveal

import (
	"context"
	"errors"
	"fmt"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/guardianstore"
	"github.com/marksisson/sphinx/internal/lockedresource"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/seeker"
	"github.com/marksisson/sphinx/internal/tombstate"
)

type SeekerResolver interface {
	Resolve(context.Context) (seeker.Identity, error)
}
type GuardianLoader interface {
	Get(guardian.Name, guardian.Provider) (*guardian.Record, error)
}

type Coordinator struct {
	Engine    artifact.Engine
	Seekers   SeekerResolver
	Guardians GuardianLoader
}

// Reveal returns a MAC- and schema-verified document. The caller owns stdout
// formatting and must destroy the returned document after emission.
func (c Coordinator) Reveal(ctx context.Context, resource *lockedresource.Artifact, configured config.ProjectTomb) (*artifact.Document, error) {
	if resource == nil || resource.Content == nil {
		return nil, fmt.Errorf("locked artifact resource is unavailable")
	}
	if configured.Lock.Commit != resource.Commit {
		return nil, fmt.Errorf("resolved artifact commit does not match the project lock")
	}
	verified, err := tombstate.Verify(resource.Content, configured.Lock.ProclamationFingerprint)
	if err != nil {
		return nil, err
	}
	if verified.Decree.Generation != configured.Lock.DecreeGeneration {
		return nil, fmt.Errorf("signed decree generation does not match the project lock")
	}
	locked, exists := findArtifactLock(verified, resource.Chamber.String())
	if !exists || locked != resource.Blob.SHA256Hex() {
		return nil, fmt.Errorf("resolved artifact does not match its signed lock")
	}

	if c.Seekers == nil {
		return nil, fmt.Errorf("live seeker resolver is unavailable")
	}
	identity, err := c.Seekers.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	if !verified.Decree.Authorizes(identity, resource.Chamber.String()) {
		return nil, fmt.Errorf("current seeker is not authorized to reveal chamber %q", resource.Chamber.String())
	}

	inspection, err := c.Engine.Inspect(resource.Blob.Data, verified.Manifest.Proclamation.AgeRecipient)
	if err != nil {
		return nil, err
	}
	if len(inspection.Recipients) == 1 {
		return nil, fmt.Errorf("artifact has zero guardian recipients and cannot be revealed")
	}
	if len(configured.Guardians) == 0 {
		return nil, fmt.Errorf("project tomb configures no guardians")
	}
	schemaBlob, exists := resource.Content.Schemas[inspection.Schema]
	if !exists {
		return nil, fmt.Errorf("artifact schema %q is absent from the locked tomb", inspection.Schema)
	}
	definition, err := schema.Decode(schemaBlob.Data)
	if err != nil {
		return nil, err
	}
	if c.Guardians == nil {
		return nil, fmt.Errorf("guardian provider loader is unavailable")
	}

	eligible := false
	for _, selection := range configured.Guardians {
		record, err := c.Guardians.Get(selection.Name, selection.Provider)
		if err != nil {
			if errors.Is(err, guardianstore.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("load configured guardian %q: %w", selection.Name, err)
		}
		recipient := record.Recipient()
		if !contains(inspection.Recipients[1:], recipient) {
			record.Destroy()
			continue
		}
		eligible = true
		ageIdentity, err := record.Identity()
		record.Destroy()
		if err != nil {
			return nil, err
		}
		document, used, err := c.Engine.DecryptWithIdentities(resource.Blob.Data, verified.Manifest.Proclamation.AgeRecipient, []*age.HybridIdentity{ageIdentity}, *definition)
		if err == nil {
			if used != recipient {
				document.Destroy()
				return nil, fmt.Errorf("artifact decrypted with an unexpected guardian recipient")
			}
			return document, nil
		}
	}
	if !eligible {
		return nil, fmt.Errorf("no configured guardian recipient intersects the artifact recipient set")
	}
	return nil, fmt.Errorf("no eligible configured guardian can unwrap the artifact data key")
}

func findArtifactLock(verified *tombstate.Verified, chamber string) (string, bool) {
	for _, lock := range verified.Decree.ArtifactLocks {
		if lock.Chamber == chamber {
			return lock.SHA256, true
		}
	}
	return "", false
}

func contains(values []string, selected string) bool {
	for _, value := range values {
		if value == selected {
			return true
		}
	}
	return false
}
