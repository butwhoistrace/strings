package categorizer

import "regexp"

var patterns = map[string]*regexp.Regexp{
	"url":          regexp.MustCompile(`https?://[^\s<>"']+|ftp://[^\s<>"']+|www\.[^\s<>"']+`),
	"email":        regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	"ipv4":         regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
	"ipv6":         regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
	"domain":       regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|onion|edu|gov|mil|co)\b`),
	"win_path":     regexp.MustCompile(`[A-Za-z]:\\(?:[^\s\\/:*?"<>|]+\\)*[^\s\\/:*?"<>|]*`),
	"unix_path":    regexp.MustCompile(`(?:/[a-zA-Z0-9._\-]+){2,}`),
	"registry":     regexp.MustCompile(`(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s]+`),
	"dll_api":      regexp.MustCompile(`(?i)\b[A-Za-z_][A-Za-z0-9_]*\.(?:dll|sys|ocx|drv)\b|\b(?:Create|Open|Read|Write|Close|Delete|Find|Get|Set|Load|Free|Virtual|Reg|Crypt|Http|Internet|Socket|WSA|Nt|Zw)[A-Z][a-zA-Z0-9_]*(?:A|W|Ex|ExA|ExW)?\b`),
	"error":        regexp.MustCompile(`(?i)\b(?:error|fail|exception|warning|assert|debug|fatal|panic|abort|denied|invalid|corrupt)\b`),
	"crypto":       regexp.MustCompile(`(?i)\b(?:AES|RSA|SHA[0-9]*|MD5|HMAC|CBC|ECB|GCM|PKCS|BEGIN\s+(?:RSA|DSA|EC|PRIVATE|PUBLIC|CERTIFICATE))\b|-----BEGIN\s[^\-]+-----`),
	"base64_blob":  regexp.MustCompile(`(?:[A-Za-z0-9+/]{20,}={0,2})`),
	"hash_md5":     regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
	"hash_sha1":    regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
	"hash_sha256":  regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
	"credential":   regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?token|bearer|credential|AWS_SECRET|AWS_ACCESS|PRIVATE[_\-]?KEY|client[_\-]?secret)\s*[=:]\s*\S+`),
	"basic_auth":   regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/=]{10,}`),
	"bearer_token": regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=\-]{10,}`),
	"port":         regexp.MustCompile(`(?i)\b(?:port|listen|bind)\s*[=:]\s*\d{1,5}\b`),
}

var suspiciousAPIs = map[string][]string{
	"process":   {"CreateProcess", "OpenProcess", "TerminateProcess", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "NtCreateProcess", "CreateThread", "SuspendThread", "ResumeThread"},
	"injection": {"SetWindowsHookEx", "CreateRemoteThread", "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread", "NtMapViewOfSection", "NtWriteVirtualMemory", "NtUnmapViewOfSection"},
	"registry":  {"RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegQueryValue", "RegEnumKey", "RegEnumValue"},
	"network":   {"WSAStartup", "socket", "connect", "send", "recv", "bind", "listen", "InternetOpen", "HttpOpenRequest", "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "getaddrinfo", "gethostbyname", "inet_addr"},
	"file":      {"CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile", "MoveFile", "FindFirstFile", "GetTempPath", "GetSystemDirectory", "CreateDirectory", "RemoveDirectory"},
	"crypto":    {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext", "BCryptEncrypt", "BCryptDecrypt", "CryptHashData", "CryptDeriveKey"},
	"evasion":   {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "GetTickCount", "Sleep", "VirtualProtect", "OutputDebugString", "NtSetInformationThread", "QueryPerformanceCounter", "GetSystemTime"},
	"privilege": {"AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "ImpersonateLoggedOnUser", "DuplicateToken", "SetThreadToken"},
	"service":   {"OpenSCManager", "CreateService", "StartService", "ControlService", "DeleteService", "ChangeServiceConfig"},
}

var OnlyPresets = map[string][]string{
	"urls":       {"url"},
	"apis":       {"dll_api"},
	"passwords":  {"credential", "basic_auth", "bearer_token"},
	"network":    {"url", "ipv4", "ipv6", "domain", "port"},
	"paths":      {"win_path", "unix_path", "registry"},
	"crypto":     {"crypto"},
	"hashes":     {"hash_md5", "hash_sha1", "hash_sha256"},
	"emails":     {"email"},
	"suspicious": {"dll_api", "credential", "basic_auth", "bearer_token", "crypto"},
}

func Categorize(s string) []string {
	var cats []string
	for name, pat := range patterns {
		if pat.MatchString(s) {
			cats = append(cats, name)
		}
	}
	if len(cats) == 0 {
		cats = append(cats, "general")
	}
	return cats
}

func GetSuspiciousGroup(s string) string {
	lower := toLower(s)
	for group, apis := range suspiciousAPIs {
		for _, api := range apis {
			if containsLower(lower, toLower(api)) {
				return group
			}
		}
	}
	return ""
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsLower(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
