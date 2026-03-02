package color

// Colorizer handles ANSI color output. When disabled, all methods return the input unchanged.
type Colorizer struct {
	Enabled bool
}

var codes = map[string]string{
	"reset":   "\033[0m",
	"bold":    "\033[1m",
	"dim":     "\033[2m",
	"red":     "\033[91m",
	"green":   "\033[92m",
	"yellow":  "\033[93m",
	"blue":    "\033[94m",
	"magenta": "\033[95m",
	"cyan":    "\033[96m",
	"white":   "\033[97m",
	"gray":    "\033[90m",
}

// Apply wraps text with the given ANSI color code.
func (c *Colorizer) Apply(text, name string) string {
	if !c.Enabled {
		return text
	}
	code, ok := codes[name]
	if !ok {
		return text
	}
	return code + text + codes["reset"]
}

// CategoryColor returns the color name for a string category.
func CategoryColor(cat string) string {
	m := map[string]string{
		"url": "blue", "email": "cyan", "ipv4": "yellow", "ipv6": "yellow",
		"domain": "blue", "win_path": "green", "unix_path": "green",
		"registry": "yellow", "dll_api": "magenta", "error": "red",
		"crypto": "magenta", "base64_blob": "cyan", "hash_md5": "yellow",
		"hash_sha1": "yellow", "hash_sha256": "yellow", "credential": "red",
		"basic_auth": "red", "bearer_token": "red", "port": "cyan", "general": "gray",
	}
	if v, ok := m[cat]; ok {
		return v
	}
	return "gray"
}
