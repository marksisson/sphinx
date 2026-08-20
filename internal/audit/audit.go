package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	Login     string    `json:"login,omitempty"`
	Node      string    `json:"node,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Path      string    `json:"path"`
	Facet     string    `json:"facet,omitempty"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason"`
}

type Logger struct {
	mu   sync.Mutex
	file *os.File
}

func Open(filename string) (*Logger, error) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure audit log permissions: %w", err)
	}
	return &Logger{file: file}, nil
}

func (l *Logger) Record(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return json.NewEncoder(l.file).Encode(event)
}

func (l *Logger) Close() error {
	return l.file.Close()
}
