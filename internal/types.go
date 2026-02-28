package internal

type StringResult struct {
	Value           string   `json:"value"`
	Offset          int64    `json:"offset"`
	Encoding        string   `json:"encoding"`
	Section         string   `json:"section,omitempty"`
	Categories      []string `json:"categories"`
	Entropy         float64  `json:"entropy"`
	EntropyLabel    string   `json:"entropy_label"`
	SuspiciousGroup string   `json:"api_group,omitempty"`
	Source          string   `json:"source"`
	XorKey          byte     `json:"xor_key,omitempty"`
	HexBefore       string   `json:"hex_before,omitempty"`
	HexAfter        string   `json:"hex_after,omitempty"`
	Length          int      `json:"length"`
}

type SectionInfo struct {
	Name           string `json:"name"`
	Offset         int64  `json:"offset"`
	Size           int64  `json:"size"`
	VirtualAddress uint64 `json:"virtual_address,omitempty"`
}

type ThreatResult struct {
	Level   string                   `json:"level"`
	Score   int                      `json:"score"`
	Details map[string]ThreatDetails `json:"details"`
}

type ThreatDetails struct {
	Count  int `json:"count"`
	Weight int `json:"weight"`
	Score  int `json:"score"`
}

type ScanConfig struct {
	MinLength  int
	Encodings  []string
	Base64     bool
	Xor        bool
	ShowOffset bool
	Context    bool
	Dedup      bool
	Filter     string
	IgnoreCase bool
	Only       string
	Quiet      bool
	Color      bool
	Json       bool
	Csv        bool
	Stats      bool
	Threat     bool
	Report     string
	DiffFile   string
}
