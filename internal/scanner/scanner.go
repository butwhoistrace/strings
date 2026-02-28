package scanner

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/butwhoistrace/strings/internal"
	"github.com/butwhoistrace/strings/internal/categorizer"
	"github.com/butwhoistrace/strings/internal/entropy"
	"github.com/butwhoistrace/strings/internal/parser"
)

var encodingPatterns = map[string]string{
	"ascii":     `[\x20-\x7e\x09]{%d,}`,
	"utf-8":     `(?:[\x20-\x7e\x09]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|[\xee-\xef][\x80-\xbf]{2}){%d,}`,
	"utf-16-le": `(?:[\x20-\x7e\x09]\x00){%d,}`,
	"utf-16-be": `(?:\x00[\x20-\x7e\x09]){%d,}`,
}

func LoadFile(filepath string) ([]byte, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		return nil, err
	}

	if info.Size() == 0 {
		return []byte{}, nil
	}

	if info.Size() < 1_000_000 {
		return os.ReadFile(filepath)
	}

	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return os.ReadFile(filepath)
	}
	return data, nil
}

func Extract(data []byte, minLen int, enc string, sections []internal.SectionInfo, filterPat *regexp.Regexp, showContext bool) []internal.StringResult {
	patStr := fmt.Sprintf(encodingPatterns[enc], minLen)
	pat := regexp.MustCompile(patStr)

	matches := pat.FindAllIndex(data, -1)
	results := make([]internal.StringResult, 0, len(matches))

	for _, loc := range matches {
		raw := data[loc[0]:loc[1]]
		s := decodeBytes(raw, enc)
		offset := int64(loc[0])

		if filterPat != nil && !filterPat.MatchString(s) {
			continue
		}

		ent := entropy.Calculate(s)
		cats := categorizer.Categorize(s)
		section := parser.GetSectionForOffset(sections, offset)
		apiGroup := categorizer.GetSuspiciousGroup(s)

		r := internal.StringResult{
			Value:           s,
			Offset:          offset,
			Encoding:        enc,
			Section:         section,
			Categories:      cats,
			Entropy:         ent,
			EntropyLabel:    entropy.Label(ent),
			SuspiciousGroup: apiGroup,
			Source:           "raw",
			Length:          len(s),
		}

		if showContext {
			r.HexBefore, r.HexAfter = hexContext(data, loc[0], loc[1]-loc[0], 16)
		}

		results = append(results, r)
	}
	return results
}

func decodeBytes(raw []byte, enc string) string {
	switch enc {
	case "ascii", "utf-8":
		return string(raw)
	case "utf-16-le":
		var sb strings.Builder
		for i := 0; i+1 < len(raw); i += 2 {
			sb.WriteByte(raw[i])
		}
		return sb.String()
	case "utf-16-be":
		var sb strings.Builder
		for i := 0; i+1 < len(raw); i += 2 {
			sb.WriteByte(raw[i+1])
		}
		return sb.String()
	}
	return string(raw)
}

func hexContext(data []byte, offset, length, ctx int) (string, string) {
	start := offset - ctx
	if start < 0 {
		start = 0
	}
	before := data[start:offset]

	end := offset + length + ctx
	if end > len(data) {
		end = len(data)
	}
	afterStart := offset + length
	if afterStart > len(data) {
		afterStart = len(data)
	}
	after := data[afterStart:end]

	return formatHex(before), formatHex(after)
}

func formatHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, " ")
}
