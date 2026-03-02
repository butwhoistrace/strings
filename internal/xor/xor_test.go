package xor

import (
	"testing"
)

func TestBruteforceEmpty(t *testing.T) {
	results := Bruteforce(nil, 6, nil, true)
	if results != nil {
		t.Errorf("expected nil for empty data, got %d results", len(results))
	}
}

func TestBruteforceFindsXORString(t *testing.T) {
	// XOR "http://malware.evil.com/payload" with key 0x42
	plain := []byte("http://malware.evil.com/payload")
	data := make([]byte, len(plain))
	for i, b := range plain {
		data[i] = b ^ 0x42
	}
	results := Bruteforce(data, 6, nil, true)
	found := false
	for _, r := range results {
		if r.Value == "http://malware.evil.com/payload" {
			found = true
			if r.XorKey != 0x42 {
				t.Errorf("xor key = 0x%02X, want 0x42", r.XorKey)
			}
			if r.Source != "xor" {
				t.Errorf("source = %q, want xor", r.Source)
			}
		}
	}
	if !found {
		t.Error("expected to find XOR'd URL string")
	}
}

func TestBruteforceIgnoresUninteresting(t *testing.T) {
	// XOR a boring string — should not match interesting pattern
	plain := []byte("this is just a normal boring string without any urls")
	data := make([]byte, len(plain))
	for i, b := range plain {
		data[i] = b ^ 0x11
	}
	results := Bruteforce(data, 6, nil, true)
	if len(results) != 0 {
		t.Errorf("expected no results for uninteresting XOR string, got %d", len(results))
	}
}

func TestBruteforceDeduplicates(t *testing.T) {
	// Same XOR'd string repeated twice
	plain := []byte("http://evil.com/test")
	chunk := make([]byte, len(plain))
	for i, b := range plain {
		chunk[i] = b ^ 0x05
	}
	data := append(chunk, 0, 0, 0)
	data = append(data, chunk...)
	results := Bruteforce(data, 6, nil, true)
	count := 0
	for _, r := range results {
		if r.Value == "http://evil.com/test" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected deduplication, got %d copies", count)
	}
}

func TestBruteforceMinLength(t *testing.T) {
	results := Bruteforce([]byte{0x01, 0x02}, 6, nil, true)
	if len(results) != 0 {
		t.Errorf("expected no results for tiny data, got %d", len(results))
	}
}
