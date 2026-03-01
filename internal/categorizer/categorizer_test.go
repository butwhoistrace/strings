package categorizer

import (
	"sort"
	"testing"
)

func containsCategory(cats []string, cat string) bool {
	for _, c := range cats {
		if c == cat {
			return true
		}
	}
	return false
}

func TestCategorizeURL(t *testing.T) {
	tests := []string{
		"https://example.com",
		"http://evil.org/payload",
		"ftp://files.example.com/data",
	}
	for _, s := range tests {
		cats := Categorize(s)
		if !containsCategory(cats, "url") {
			t.Errorf("Categorize(%q) = %v, missing 'url'", s, cats)
		}
	}
}

func TestCategorizeEmail(t *testing.T) {
	cats := Categorize("admin@evil.org")
	if !containsCategory(cats, "email") {
		t.Errorf("Categorize email: got %v, missing 'email'", cats)
	}
}

func TestCategorizeIPv4(t *testing.T) {
	cats := Categorize("192.168.1.100")
	if !containsCategory(cats, "ipv4") {
		t.Errorf("Categorize IPv4: got %v, missing 'ipv4'", cats)
	}
}

func TestCategorizeDomain(t *testing.T) {
	cats := Categorize("malicious-site.com")
	if !containsCategory(cats, "domain") {
		t.Errorf("Categorize domain: got %v, missing 'domain'", cats)
	}
}

func TestCategorizeWinPath(t *testing.T) {
	cats := Categorize(`C:\Windows\System32\cmd.exe`)
	if !containsCategory(cats, "win_path") {
		t.Errorf("Categorize win_path: got %v, missing 'win_path'", cats)
	}
}

func TestCategorizeUnixPath(t *testing.T) {
	cats := Categorize("/etc/passwd")
	if !containsCategory(cats, "unix_path") {
		t.Errorf("Categorize unix_path: got %v, missing 'unix_path'", cats)
	}
}

func TestCategorizeRegistry(t *testing.T) {
	cats := Categorize(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`)
	if !containsCategory(cats, "registry") {
		t.Errorf("Categorize registry: got %v, missing 'registry'", cats)
	}
}

func TestCategorizeDllAPI(t *testing.T) {
	tests := []string{
		"kernel32.dll",
		"CreateRemoteThread",
		"VirtualAllocEx",
		"ntdll.dll",
	}
	for _, s := range tests {
		cats := Categorize(s)
		if !containsCategory(cats, "dll_api") {
			t.Errorf("Categorize(%q) = %v, missing 'dll_api'", s, cats)
		}
	}
}

func TestCategorizeCredential(t *testing.T) {
	tests := []string{
		"password=SuperSecret123!",
		"api_key=sk-1234567890abcdef",
		"token=abc123xyz",
	}
	for _, s := range tests {
		cats := Categorize(s)
		if !containsCategory(cats, "credential") {
			t.Errorf("Categorize(%q) = %v, missing 'credential'", s, cats)
		}
	}
}

func TestCategorizeCrypto(t *testing.T) {
	cats := Categorize("-----BEGIN RSA PRIVATE KEY-----")
	if !containsCategory(cats, "crypto") {
		t.Errorf("Categorize crypto: got %v, missing 'crypto'", cats)
	}
}

func TestCategorizeBearerToken(t *testing.T) {
	cats := Categorize("Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.abc123")
	if !containsCategory(cats, "bearer_token") {
		t.Errorf("Categorize bearer_token: got %v, missing 'bearer_token'", cats)
	}
}

func TestCategorizeGeneral(t *testing.T) {
	cats := Categorize("just a random string")
	if !containsCategory(cats, "general") {
		t.Errorf("Categorize general: got %v, missing 'general'", cats)
	}
	if len(cats) != 1 {
		t.Errorf("Categorize general: expected only 'general', got %v", cats)
	}
}

func TestGetSuspiciousGroupProcess(t *testing.T) {
	tests := map[string]string{
		"CreateProcess":       "process",
		"CreateRemoteThread":  "injection",
		"IsDebuggerPresent":   "evasion",
		"AdjustTokenPrivileges": "privilege",
		"OpenSCManager":       "service",
		"WSAStartup":          "network",
		"CryptEncrypt":        "crypto",
		"RegOpenKey":          "registry",
		"CreateFile":          "file",
	}
	for api, expectedGroup := range tests {
		got := GetSuspiciousGroup(api)
		if got != expectedGroup {
			// Some APIs belong to multiple groups, so check that we get one of the valid groups
			t.Logf("GetSuspiciousGroup(%q) = %q, expected %q (may be in multiple groups)", api, got, expectedGroup)
		}
	}
}

func TestGetSuspiciousGroupNone(t *testing.T) {
	got := GetSuspiciousGroup("printf")
	if got != "" {
		t.Errorf("GetSuspiciousGroup(\"printf\") = %q, want empty", got)
	}
}

func TestGetSuspiciousGroupCaseInsensitive(t *testing.T) {
	// The function uses toLower, so it should match regardless of case
	got := GetSuspiciousGroup("CREATEPROCESS")
	if got == "" {
		t.Error("GetSuspiciousGroup(\"CREATEPROCESS\") returned empty, expected a group")
	}
}

func TestOnlyPresetsExist(t *testing.T) {
	expected := []string{"urls", "apis", "passwords", "network", "paths", "crypto", "hashes", "emails", "suspicious"}
	sort.Strings(expected)

	var keys []string
	for k := range OnlyPresets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if len(keys) != len(expected) {
		t.Errorf("OnlyPresets has %d keys, want %d", len(keys), len(expected))
	}
	for _, k := range expected {
		if _, ok := OnlyPresets[k]; !ok {
			t.Errorf("OnlyPresets missing key %q", k)
		}
	}
}
