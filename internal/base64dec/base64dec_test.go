package base64dec

import (
	"encoding/base64"
	"testing"
)

func TestExtractValid(t *testing.T) {
	// "Hello, World!" base64 encoded = "SGVsbG8sIFdvcmxkIQ=="
	encoded := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))
	data := []byte("prefix " + encoded + " suffix")
	results := Extract(data, 4, nil)
	found := false
	for _, r := range results {
		if r.Value == "Hello, World!" {
			found = true
			if r.Source != "base64" {
				t.Errorf("source = %q, want base64", r.Source)
			}
			if r.Encoding != "base64" {
				t.Errorf("encoding = %q, want base64", r.Encoding)
			}
		}
	}
	if !found {
		t.Errorf("expected decoded 'Hello, World!' in results, got %v", results)
	}
}

func TestExtractBinaryContent(t *testing.T) {
	// Base64 of non-printable bytes — should be filtered out (< 70% printable)
	binary := make([]byte, 30)
	for i := range binary {
		binary[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(binary)
	data := []byte(encoded)
	results := Extract(data, 4, nil)
	if len(results) != 0 {
		t.Errorf("expected no results for binary base64, got %d", len(results))
	}
}

func TestExtractShortString(t *testing.T) {
	// Very short base64 that decodes to less than minLen
	encoded := base64.StdEncoding.EncodeToString([]byte("ab"))
	data := []byte(encoded)
	results := Extract(data, 4, nil)
	if len(results) != 0 {
		t.Errorf("expected no results for short decoded string, got %d", len(results))
	}
}

func TestExtractEmpty(t *testing.T) {
	results := Extract(nil, 4, nil)
	if len(results) != 0 {
		t.Errorf("expected no results for nil data, got %d", len(results))
	}
}

func TestExtractNoBase64(t *testing.T) {
	data := []byte("just a normal string with no base64")
	results := Extract(data, 4, nil)
	// May or may not find patterns — just ensure no crash
	_ = results
}

func TestExtractMultiple(t *testing.T) {
	s1 := base64.StdEncoding.EncodeToString([]byte("first decoded string here"))
	s2 := base64.StdEncoding.EncodeToString([]byte("second decoded string here"))
	data := []byte(s1 + "\x00\x00\x00" + s2)
	results := Extract(data, 4, nil)
	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}
}
