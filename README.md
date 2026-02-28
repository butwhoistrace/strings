# strings

Binary string extractor for PE/ELF files. Like Linux `strings` but with categorization, entropy analysis, base64 decoding, XOR bruteforce, threat assessment and more.

Written in Go. Single binary, no dependencies.

## Install

```bash
go install github.com/butwhoistrace/strings/cmd/strings@latest
```

That's it. Now use `strings` from anywhere.

### Build from source

```bash
git clone https://github.com/butwhoistrace/strings.git
cd strings
go build -o strings.exe ./cmd/strings/
```

## Usage

```bash
strings <file> [options]
```

## Options

| Flag | Description |
|---|---|
| `-a` | Scan all encodings (ASCII, UTF-8, UTF-16-LE/BE) |
| `-n <num>` | Minimum string length (default: 4) |
| `-e <enc>` | Specific encoding |
| `-d` | Remove duplicate strings |
| `-o` | Show byte offsets |
| `-q` | Quiet mode |
| `-base64` | Decode base64 strings |
| `-xor` | XOR single-byte bruteforce (255 keys) |
| `-context` | Show hex bytes before/after each string |
| `-stats` | Show statistics |
| `-threat` | Threat level assessment |
| `-diff <file>` | Compare strings between two files |
| `-color` | Colored terminal output |
| `-json` | JSON output |
| `-csv` | CSV output |
| `-report <file>` | Generate interactive HTML report |
| `-f <regex>` | Regex filter |
| `-i` | Case-insensitive filter |

## Category Filter (-only)

```bash
strings file.exe -only urls          # URLs
strings file.exe -only apis          # Windows API calls
strings file.exe -only passwords     # credentials, tokens, keys
strings file.exe -only network       # URLs, IPs, domains, ports
strings file.exe -only paths         # file paths, registry keys
strings file.exe -only crypto        # crypto keys, certificates
strings file.exe -only hashes        # MD5, SHA1, SHA256
strings file.exe -only emails        # email addresses
strings file.exe -only suspicious    # high entropy + APIs + creds
strings file.exe -only urls,passwords,network  # combine
```

## Examples

```bash
# full scan
strings malware.exe -a -d -base64 -xor -stats -threat -color

# html report
strings malware.exe -a -d -base64 -xor -report report.html

# only interesting stuff
strings app.exe -a -only suspicious -threat -color

# compare two versions
strings app_v1.exe -diff app_v2.exe -color

# pipe friendly
strings file.exe -only urls -a -d -q | sort -u

# export
strings file.exe -a -d -json > results.json
strings file.exe -a -d -csv > results.csv
```

## Features

- **Auto-categorization** — URLs, emails, IPs, domains, paths, registry keys, DLLs, API calls, errors, crypto patterns, credentials, hashes
- **Entropy analysis** — Shannon entropy per string (detects base64, crypto keys, passwords)
- **PE/ELF section awareness** — Shows which section each string belongs to
- **Multi-encoding** — ASCII, UTF-8, UTF-16-LE, UTF-16-BE
- **Base64 decoding** — Finds and decodes base64 blobs
- **XOR bruteforce** — Tests all 255 single-byte XOR keys
- **Threat assessment** — Automatic threat level (LOW/MEDIUM/HIGH/CRITICAL)
- **File diff** — Compare strings between two binaries
- **Hex context** — 16 bytes before/after each string
- **HTML report** — Interactive dashboard with filters, search, sort, export
- **Colored output** — ANSI terminal colors
- **Quiet mode** — Clean output for pipes

## Threat Assessment

| Indicator | Weight |
|---|---|
| Code injection APIs | 5x |
| Evasion/anti-debug APIs | 4x |
| Privilege escalation APIs | 4x |
| XOR obfuscated strings | 4x |
| Credentials/tokens | 3x |
| Service manipulation APIs | 3x |
| Process manipulation APIs | 2x |
| Network APIs | 2x |
| High entropy strings | 2x |
| Crypto APIs | 2x |

| Score | Level |
|---|---|
| 0-9 | LOW |
| 10-29 | MEDIUM |
| 30-69 | HIGH |
| 70+ | CRITICAL |

## License

MIT
