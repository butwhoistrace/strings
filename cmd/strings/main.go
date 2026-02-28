package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/butwhoistrace/strings/internal"
	"github.com/butwhoistrace/strings/internal/base64dec"
	"github.com/butwhoistrace/strings/internal/categorizer"
	"github.com/butwhoistrace/strings/internal/diff"
	"github.com/butwhoistrace/strings/internal/parser"
	"github.com/butwhoistrace/strings/internal/report"
	"github.com/butwhoistrace/strings/internal/scanner"
	"github.com/butwhoistrace/strings/internal/threat"
	"github.com/butwhoistrace/strings/internal/xor"
)

var (
	minLength  = flag.Int("n", 4, "minimum string length")
	encoding   = flag.String("e", "ascii", "encoding (ascii, utf-8, utf-16-le, utf-16-be)")
	allEnc     = flag.Bool("a", false, "scan all encodings")
	base64Flag = flag.Bool("base64", false, "decode base64 strings")
	xorFlag    = flag.Bool("xor", false, "xor single-byte bruteforce")
	only       = flag.String("only", "", "filter by category (urls,apis,passwords,network,paths,crypto,hashes,emails,suspicious)")
	diffFile   = flag.String("diff", "", "compare with another file")
	filter     = flag.String("f", "", "regex filter")
	ignoreCase = flag.Bool("i", false, "case-insensitive filter")
	dedup      = flag.Bool("d", false, "remove duplicates")
	offset     = flag.Bool("o", false, "show offsets")
	context    = flag.Bool("context", false, "show hex context")
	jsonOut    = flag.Bool("json", false, "json output")
	csvOut     = flag.Bool("csv", false, "csv output")
	stats      = flag.Bool("stats", false, "show statistics")
	threatFlag = flag.Bool("threat", false, "threat assessment")
	reportFile = flag.String("report", "", "generate html report")
	color      = flag.Bool("color", false, "colored output")
	quiet      = flag.Bool("q", false, "quiet mode")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "strings - advanced binary string extractor\n\n")
		fmt.Fprintf(os.Stderr, "usage: strings <file> [options]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\npresets for --only:\n")
		fmt.Fprintf(os.Stderr, "  urls, apis, passwords, network, paths, crypto, hashes, emails, suspicious\n")
		fmt.Fprintf(os.Stderr, "\nexamples:\n")
		fmt.Fprintf(os.Stderr, "  strings file.exe -a --base64 --xor --report report.html\n")
		fmt.Fprintf(os.Stderr, "  strings file.exe --only urls,passwords -a --color\n")
		fmt.Fprintf(os.Stderr, "  strings file.exe --only suspicious --threat --color\n")
		fmt.Fprintf(os.Stderr, "  strings app_v1.exe --diff app_v2.exe --color\n")
	}

	args := os.Args[1:]
	var files []string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				needsVal := a == "-n" || a == "-e" || a == "-f" || a == "--only" || a == "--diff" || a == "--report" ||
					a == "-only" || a == "-diff" || a == "-report" || a == "-filter"
				if needsVal {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			files = append(files, a)
		}
	}
	flag.CommandLine.Parse(flagArgs)

	if len(files) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if *diffFile != "" {
		handleDiff(files[0], *diffFile)
		return
	}

	for _, fp := range files {
		results, sections := processFile(fp)
		if results == nil {
			continue
		}
		outputResults(results, sections, fp)
	}
}

func processFile(fp string) ([]internal.StringResult, []internal.SectionInfo) {
	info, err := os.Stat(fp)
	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  error: %s not found\n", fp)
		}
		return nil, nil
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "  scanning: %s (%s)\n", fp, formatSize(info.Size()))
	}

	sections := parser.ParseSections(fp)
	if len(sections) > 0 && !*quiet {
		fmt.Fprintf(os.Stderr, "  format: %s | %d sections\n", parser.FormatType(fp), len(sections))
	}

	encodings := []string{*encoding}
	if *allEnc {
		encodings = []string{"ascii", "utf-8", "utf-16-le", "utf-16-be"}
	}

	var filterPat *regexp.Regexp
	if *filter != "" {
		flags := ""
		if *ignoreCase {
			flags = "(?i)"
		}
		filterPat = regexp.MustCompile(flags + *filter)
	}

	var onlyCats map[string]bool
	if *only != "" {
		onlyCats = make(map[string]bool)
		for _, preset := range strings.Split(*only, ",") {
			preset = strings.TrimSpace(strings.ToLower(preset))
			if cats, ok := categorizer.OnlyPresets[preset]; ok {
				for _, c := range cats {
					onlyCats[c] = true
				}
			} else {
				onlyCats[preset] = true
			}
		}
	}

	data, err := scanner.LoadFile(fp)
	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  error loading file: %v\n", err)
		}
		return nil, nil
	}

	var allResults []internal.StringResult
	seen := make(map[string]bool)

	for _, enc := range encodings {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  encoding: %s\n", enc)
		}
		results := scanner.Extract(data, *minLength, enc, sections, filterPat, *context)
		for _, r := range results {
			if *dedup && seen[r.Value] {
				continue
			}
			if onlyCats != nil && !matchOnly(r, onlyCats) {
				continue
			}
			seen[r.Value] = true
			allResults = append(allResults, r)
		}
	}

	if *base64Flag {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  base64 decoding...\n")
		}
		for _, r := range base64dec.Extract(data, *minLength, sections) {
			if *dedup && seen[r.Value] {
				continue
			}
			seen[r.Value] = true
			allResults = append(allResults, r)
		}
	}

	if *xorFlag {
		ml := *minLength
		if ml < 6 {
			ml = 6
		}
		for _, r := range xor.Bruteforce(data, ml, sections, *quiet) {
			if *dedup && seen[r.Value] {
				continue
			}
			seen[r.Value] = true
			allResults = append(allResults, r)
		}
	}

	return allResults, sections
}

func matchOnly(r internal.StringResult, onlyCats map[string]bool) bool {
	for _, c := range r.Categories {
		if onlyCats[c] {
			return true
		}
	}
	if onlyCats["dll_api"] && r.SuspiciousGroup != "" {
		return true
	}
	return false
}

func outputResults(results []internal.StringResult, sections []internal.SectionInfo, fp string) {
	if *reportFile != "" {
		if err := report.Generate(results, fp, sections, *reportFile); err != nil {
			fmt.Fprintf(os.Stderr, "  error generating report: %v\n", err)
		} else if !*quiet {
			fmt.Fprintf(os.Stderr, "  report: %s\n", *reportFile)
		}
	} else if *jsonOut {
		printJSON(results, fp)
	} else if *csvOut {
		printCSV(results)
	} else {
		printText(results)
	}

	if *stats {
		printStats(results, fp, sections)
	}
	if *threatFlag {
		printThreat(results)
	}
}

func printText(results []internal.StringResult) {
	for _, r := range results {
		var parts []string

		if *offset {
			parts = append(parts, col(fmt.Sprintf("0x%08X", r.Offset), "gray"))
		}
		if r.Section != "" {
			parts = append(parts, col(fmt.Sprintf("[%s]", r.Section), "dim"))
		}
		if r.Source != "raw" {
			src := fmt.Sprintf("[%s", r.Source)
			if r.Source == "xor" {
				src += fmt.Sprintf(" 0x%02X", r.XorKey)
			}
			src += "]"
			sc := "cyan"
			if r.Source == "xor" {
				sc = "red"
			}
			parts = append(parts, col(src, sc))
		}

		var tags []string
		for _, c := range r.Categories {
			if c != "general" {
				tags = append(tags, col(c, catColor(c)))
			}
		}
		if len(tags) > 0 {
			parts = append(parts, strings.Join(tags, " "))
		}
		if r.Entropy >= 4.5 {
			parts = append(parts, col(fmt.Sprintf("H:%.1f", r.Entropy), "red"))
		}

		parts = append(parts, r.Value)
		fmt.Println(strings.Join(parts, "  "))

		if *context && (r.HexBefore != "" || r.HexAfter != "") {
			fmt.Printf("    %s %s\n", col("before:", "dim"), r.HexBefore)
			fmt.Printf("    %s  %s\n", col("after:", "dim"), r.HexAfter)
		}
	}
}

func printJSON(results []internal.StringResult, fp string) {
	t := threat.Assess(results)
	out := struct {
		File    string                  `json:"file"`
		Count   int                     `json:"count"`
		Threat  internal.ThreatResult   `json:"threat"`
		Strings []internal.StringResult `json:"strings"`
	}{fp, len(results), t, results}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(out)
}

func printCSV(results []internal.StringResult) {
	w := csv.NewWriter(os.Stdout)
	w.Write([]string{"offset", "encoding", "section", "categories", "entropy", "source", "xor_key", "api_group", "value"})
	for _, r := range results {
		w.Write([]string{
			fmt.Sprintf("%d", r.Offset), r.Encoding, r.Section,
			strings.Join(r.Categories, ";"), fmt.Sprintf("%.2f", r.Entropy),
			r.Source, fmt.Sprintf("%d", r.XorKey), r.SuspiciousGroup, r.Value,
		})
	}
	w.Flush()
}

func printStats(results []internal.StringResult, fp string, sections []internal.SectionInfo) {
	catCounts := make(map[string]int)
	for _, r := range results {
		for _, c := range r.Categories {
			catCounts[c]++
		}
	}
	srcCounts := make(map[string]int)
	highEnt := 0
	susCount := 0
	for _, r := range results {
		srcCounts[r.Source]++
		if r.Entropy >= 4.5 {
			highEnt++
		}
		if r.SuspiciousGroup != "" {
			susCount++
		}
	}

	W := 54
	fmt.Fprintf(os.Stderr, "\n  %s\n", strings.Repeat("=", W))
	fmt.Fprintf(os.Stderr, "  %s\n", col(filepath.Base(fp), "bold"))
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Total strings:       %8d\n", len(results))
	fmt.Fprintf(os.Stderr, "  High entropy (>=4.5):%8d\n", highEnt)
	fmt.Fprintf(os.Stderr, "  Suspicious APIs:     %8d\n", susCount)
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Sources:\n")
	for src, cnt := range srcCounts {
		fmt.Fprintf(os.Stderr, "    %-12s  %8d\n", src, cnt)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Top categories:\n")
	for cat, cnt := range catCounts {
		fmt.Fprintf(os.Stderr, "    %-20s  %8d\n", col(cat, catColor(cat)), cnt)
	}
	if len(sections) > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
		fmt.Fprintf(os.Stderr, "  Sections:\n")
		for _, sec := range sections {
			fmt.Fprintf(os.Stderr, "    %-12s  offset=0x%08X  size=%s\n", sec.Name, sec.Offset, formatSize(sec.Size))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("=", W))
}

func printThreat(results []internal.StringResult) {
	t := threat.Assess(results)
	lc := map[string]string{"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "red"}[t.Level]

	fmt.Fprintf(os.Stderr, "\n  %s\n", strings.Repeat("=", 54))
	fmt.Fprintf(os.Stderr, "  %s\n", col("THREAT ASSESSMENT", "bold"))
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("=", 54))
	fmt.Fprintf(os.Stderr, "  Level: %s (score: %d)\n", col(t.Level, lc), t.Score)
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 54))
	if len(t.Details) > 0 {
		fmt.Fprintf(os.Stderr, "  %-28s %6s %7s %6s\n", "Indicator", "Count", "Weight", "Score")
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 54))
		for ind, d := range t.Details {
			fmt.Fprintf(os.Stderr, "  %-28s %6d %5dx %6d\n", ind, d.Count, d.Weight, d.Score)
		}
	} else {
		fmt.Fprintf(os.Stderr, "  No suspicious indicators found.\n")
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", strings.Repeat("=", 54))
}

func handleDiff(fileA, fileB string) {
	resA, _ := processFile(fileA)
	resB, _ := processFile(fileB)
	if resA == nil || resB == nil {
		return
	}
	d := diff.Compare(resA, resB)
	diff.Print(d, fileA, fileB, *color)
}

func col(text, c string) string {
	if !*color {
		return text
	}
	codes := map[string]string{
		"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
		"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
		"blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
		"white": "\033[97m", "gray": "\033[90m",
	}
	code, ok := codes[c]
	if !ok {
		return text
	}
	return code + text + codes["reset"]
}

func catColor(c string) string {
	m := map[string]string{
		"url": "blue", "email": "cyan", "ipv4": "yellow", "ipv6": "yellow",
		"domain": "blue", "win_path": "green", "unix_path": "green",
		"registry": "yellow", "dll_api": "magenta", "error": "red",
		"crypto": "magenta", "base64_blob": "cyan", "hash_md5": "yellow",
		"hash_sha1": "yellow", "hash_sha256": "yellow", "credential": "red",
		"basic_auth": "red", "bearer_token": "red", "port": "cyan", "general": "gray",
	}
	if v, ok := m[c]; ok {
		return v
	}
	return "gray"
}

func formatSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	s := float64(size)
	for _, u := range units {
		if s < 1024 {
			return fmt.Sprintf("%.1f %s", s, u)
		}
		s /= 1024
	}
	return fmt.Sprintf("%.1f TB", s)
}
