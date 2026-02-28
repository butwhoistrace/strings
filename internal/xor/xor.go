package xor

import (
	"fmt"
	"os"
	"regexp"

	"github.com/butwhoistrace/strings/internal"
	"github.com/butwhoistrace/strings/internal/categorizer"
	"github.com/butwhoistrace/strings/internal/entropy"
	"github.com/butwhoistrace/strings/internal/parser"
)

var interestingPattern = regexp.MustCompile(`(?i)https?://|\.exe\b|\.dll\b|\.bat\b|\.cmd\b|\.ps1\b|cmd\.exe|powershell|\\windows\\|password|username|admin|HKEY_|BEGIN\s+(?:RSA|CERTIFICATE|PRIVATE)|api[_\-]?key|secret|token|\.onion\b|socket|connect`)

func Bruteforce(data []byte, minLen int, sections []internal.SectionInfo, quiet bool) []internal.StringResult {
	asciiPat := regexp.MustCompile(fmt.Sprintf(`[\x20-\x7e\x09]{%d,}`, minLen))
	seen := make(map[string]bool)
	var results []internal.StringResult

	if !quiet {
		fmt.Fprint(os.Stderr, "  xor bruteforce: testing 255 keys...")
	}

	xored := make([]byte, len(data))

	for key := 1; key <= 255; key++ {
		for i, b := range data {
			xored[i] = b ^ byte(key)
		}

		matches := asciiPat.FindAllIndex(xored, -1)
		for _, loc := range matches {
			s := string(xored[loc[0]:loc[1]])
			if !interestingPattern.MatchString(s) || seen[s] {
				continue
			}
			seen[s] = true
			offset := int64(loc[0])
			ent := entropy.Calculate(s)

			results = append(results, internal.StringResult{
				Value:           s,
				Offset:          offset,
				Encoding:        "ascii",
				Section:         parser.GetSectionForOffset(sections, offset),
				Categories:      categorizer.Categorize(s),
				Entropy:         ent,
				EntropyLabel:    entropy.Label(ent),
				SuspiciousGroup: categorizer.GetSuspiciousGroup(s),
				Source:          "xor",
				XorKey:          byte(key),
				Length:          len(s),
			})
		}

		if !quiet && key%32 == 0 {
			fmt.Fprint(os.Stderr, ".")
		}
	}

	if !quiet {
		fmt.Fprintln(os.Stderr, " done")
	}
	return results
}
