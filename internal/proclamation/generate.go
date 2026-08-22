package proclamation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	wordCount        = 10
	wordlistEntries  = 7776
	wordlistChecksum = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
)

//go:embed eff_large_wordlist.txt
var wordlistBytes []byte

var (
	wordsOnce sync.Once
	words     []string
	wordsErr  error
)

func Generate(source io.Reader) (Credential, error) {
	list, _, err := loadWords()
	if err != nil {
		return Credential{}, err
	}
	if source == nil {
		source = rand.Reader
	}
	selected := make([]string, wordCount)
	for index := range selected {
		wordIndex, err := unbiasedIndex(source, len(list))
		if err != nil {
			return Credential{}, fmt.Errorf("generate proclamation: %w", err)
		}
		selected[index] = list[wordIndex]
	}
	var phrase []byte
	for index, word := range selected {
		if index > 0 {
			phrase = append(phrase, ' ')
		}
		phrase = append(phrase, word...)
	}
	credential := NewCredential(phrase)
	clear(phrase)
	return credential, nil
}

func validatePhrase(value []byte) error {
	_, allowed, err := loadWords()
	if err != nil {
		return err
	}
	parts := bytes.Split(value, []byte{' '})
	if len(parts) != wordCount {
		return fmt.Errorf("proclamation must contain exactly ten pinned-list words separated by one ASCII space")
	}
	for _, word := range parts {
		if !allowed[string(word)] {
			return fmt.Errorf("proclamation contains a word outside the pinned list")
		}
	}
	return nil
}

func loadWords() ([]string, map[string]bool, error) {
	wordsOnce.Do(func() {
		digest := sha256.Sum256(wordlistBytes)
		if hex.EncodeToString(digest[:]) != wordlistChecksum {
			wordsErr = fmt.Errorf("embedded proclamation wordlist checksum mismatch")
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(wordlistBytes), "\n"), "\n")
		if len(lines) != wordlistEntries {
			wordsErr = fmt.Errorf("embedded proclamation wordlist has %d entries, want %d", len(lines), wordlistEntries)
			return
		}
		words = make([]string, len(lines))
		seen := make(map[string]bool, len(lines))
		for index, line := range lines {
			parts := strings.Split(line, "\t")
			if len(parts) != 2 || parts[1] == "" || seen[parts[1]] {
				wordsErr = fmt.Errorf("embedded proclamation wordlist entry %d is malformed", index+1)
				return
			}
			seen[parts[1]] = true
			words[index] = parts[1]
		}
	})
	if wordsErr != nil {
		return nil, nil, wordsErr
	}
	allowed := make(map[string]bool, len(words))
	for _, word := range words {
		allowed[word] = true
	}
	return words, allowed, nil
}

func unbiasedIndex(source io.Reader, count int) (int, error) {
	limit := 65536 / count * count
	var sample [2]byte
	for {
		if _, err := io.ReadFull(source, sample[:]); err != nil {
			return 0, err
		}
		value := int(sample[0])<<8 | int(sample[1])
		if value < limit {
			return value % count, nil
		}
	}
}
