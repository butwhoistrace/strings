package base64dec

import (
	"encoding/base64"
	"regexp"

	"github.com/butwhoistrace/strings/internal"
	"github.com/butwhoistrace/strings/internal/categorizer"
	"github.com/butwhoistrace/strings/internal/entropy"
	"github.com/butwhoistrace/strings/internal/parser"
)

var b64Pattern = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)

func Extract(data []byte, minLen int, sections []internal.SectionInfo) []internal.StringResult {
	matches := b64Pattern.FindAllIndex(data, -1)
	var results []internal.StringResult

	for _, loc := range matches {
		raw := data[loc[0]:loc[1]]
		padding := (4 - len(raw)%4) % 4
		padded := make([]byte, len(raw)+padding)
		copy(padded, raw)
		for i := len(raw); i < len(padded); i++ {
			padded[i] = '='
		}

		decoded, err := base64.StdEncoding.DecodeString(string(padded))
		if err != nil {
			continue
		}

		printable := 0
		for _, b := range decoded {
			if (b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a || b == 0x0d {
				printable++
			}
		}

		if len(decoded) < minLen {
			continue
		}
		if float64(printable)/float64(len(decoded)) < 0.7 {
			continue
		}

		s := string(decoded)
		ent := entropy.Calculate(s)
		offset := int64(loc[0])

		results = append(results, internal.StringResult{
			Value:           s,
			Offset:          offset,
			Encoding:        "base64",
			Section:         parser.GetSectionForOffset(sections, offset),
			Categories:      categorizer.Categorize(s),
			Entropy:         ent,
			EntropyLabel:    entropy.Label(ent),
			SuspiciousGroup: categorizer.GetSuspiciousGroup(s),
			Source:          "base64",
			Length:          len(s),
		})
	}
	return results
}
