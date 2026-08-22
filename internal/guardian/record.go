package guardian

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/hybridage"
)

const RecordVersion = 1

type Record struct {
	name        Name
	identity    []byte
	recipient   string
	fingerprint string
	createdAt   time.Time
}

type recordWire struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Suite       string `json:"suite"`
	Identity    string `json:"identity"`
	Recipient   string `json:"recipient"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
}

func NewRecord(name Name, identity *age.HybridIdentity, createdAt time.Time) (*Record, error) {
	if _, err := ParseName(string(name)); err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, fmt.Errorf("guardian hybrid identity is required")
	}
	parsed, err := hybridage.ParseIdentity(identity.String())
	if err != nil {
		return nil, err
	}
	recipient := hybridage.Recipient(parsed)
	fingerprint, err := hybridage.Fingerprint(recipient)
	if err != nil {
		return nil, err
	}
	if createdAt.IsZero() || createdAt.Location() != time.UTC {
		return nil, fmt.Errorf("guardian creation time must be nonzero UTC")
	}
	return &Record{name: name, identity: []byte(parsed.String()), recipient: recipient, fingerprint: fingerprint, createdAt: createdAt}, nil
}

func GenerateRecord(name Name, now time.Time) (*Record, error) {
	identity, err := hybridage.Generate()
	if err != nil {
		return nil, err
	}
	return NewRecord(name, identity, now.UTC())
}

func ParseRecord(data []byte) (*Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire recordWire
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode guardian record: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if wire.Version != RecordVersion || wire.Suite != hybridage.Suite {
		return nil, fmt.Errorf("guardian record version or suite is unsupported")
	}
	name, err := ParseName(wire.Name)
	if err != nil {
		return nil, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != wire.CreatedAt {
		return nil, fmt.Errorf("guardian record creation time is not canonical UTC")
	}
	identity, err := hybridage.ParseIdentity(wire.Identity)
	if err != nil {
		return nil, err
	}
	recipient := hybridage.Recipient(identity)
	fingerprint, err := hybridage.Fingerprint(recipient)
	if err != nil {
		return nil, err
	}
	if wire.Recipient != recipient || wire.Fingerprint != fingerprint {
		return nil, fmt.Errorf("guardian record derived metadata does not match its private identity")
	}
	record := &Record{name: name, identity: []byte(wire.Identity), recipient: recipient, fingerprint: fingerprint, createdAt: createdAt}
	canonical, err := record.MarshalJSON()
	if err != nil {
		record.Destroy()
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		record.Destroy()
		return nil, fmt.Errorf("guardian record JSON is not canonical")
	}
	return record, nil
}

func (r *Record) MarshalJSON() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("guardian record is unavailable")
	}
	identity, err := hybridage.ParseIdentity(string(r.identity))
	if err != nil {
		return nil, err
	}
	if hybridage.Recipient(identity) != r.recipient {
		return nil, fmt.Errorf("guardian record identity and recipient differ")
	}
	return json.Marshal(recordWire{Version: RecordVersion, Name: string(r.name), Suite: hybridage.Suite,
		Identity: string(r.identity), Recipient: r.recipient, Fingerprint: r.fingerprint,
		CreatedAt: r.createdAt.Format(time.RFC3339Nano)})
}

func (*Record) String() string   { return "[REDACTED GUARDIAN RECORD]" }
func (*Record) GoString() string { return "[REDACTED GUARDIAN RECORD]" }

func (r *Record) Name() Name           { return r.name }
func (r *Record) Suite() string        { return hybridage.Suite }
func (r *Record) Recipient() string    { return r.recipient }
func (r *Record) Fingerprint() string  { return r.fingerprint }
func (r *Record) CreatedAt() time.Time { return r.createdAt }

func (r *Record) Identity() (*age.HybridIdentity, error) {
	if r == nil {
		return nil, fmt.Errorf("guardian record is unavailable")
	}
	return hybridage.ParseIdentity(string(r.identity))
}

func (r *Record) Destroy() {
	if r == nil {
		return
	}
	clear(r.identity)
	r.identity = nil
	r.recipient = ""
	r.fingerprint = ""
	r.name = ""
	r.createdAt = time.Time{}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("guardian record contains multiple JSON values")
		}
		return fmt.Errorf("decode guardian record: %w", err)
	}
	return nil
}
