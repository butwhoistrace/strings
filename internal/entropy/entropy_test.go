package entropy

import (
	"math"
	"testing"
)

func TestCalculateEmpty(t *testing.T) {
	if got := Calculate(""); got != 0.0 {
		t.Errorf("Calculate(\"\") = %f, want 0.0", got)
	}
}

func TestCalculateSingleChar(t *testing.T) {
	if got := Calculate("a"); got != 0.0 {
		t.Errorf("Calculate(\"a\") = %f, want 0.0", got)
	}
}

func TestCalculateRepeated(t *testing.T) {
	if got := Calculate("aaaa"); got != 0.0 {
		t.Errorf("Calculate(\"aaaa\") = %f, want 0.0", got)
	}
}

func TestCalculateTwoChars(t *testing.T) {
	// "ab" has max entropy for 2 symbols = 1.0
	got := Calculate("ab")
	if got != 1.0 {
		t.Errorf("Calculate(\"ab\") = %f, want 1.0", got)
	}
}

func TestCalculateHighEntropy(t *testing.T) {
	// A string with many unique characters should have high entropy
	s := "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789"
	got := Calculate(s)
	if got < 5.0 {
		t.Errorf("Calculate(high entropy string) = %f, want >= 5.0", got)
	}
}

func TestCalculateKnownValue(t *testing.T) {
	// "aabb" -> freq: a=2, b=2, len=4
	// entropy = -(2/4 * log2(2/4)) * 2 = -(0.5 * -1) * 2 = 1.0
	got := Calculate("aabb")
	if got != 1.0 {
		t.Errorf("Calculate(\"aabb\") = %f, want 1.0", got)
	}
}

func TestCalculateRounding(t *testing.T) {
	got := Calculate("abc")
	// Should be rounded to 2 decimal places
	rounded := math.Round(got*100) / 100
	if got != rounded {
		t.Errorf("Calculate result %f is not rounded to 2 decimal places", got)
	}
}

func TestLabelLow(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{0.0, "low"},
		{1.0, "low"},
		{2.49, "low"},
	}
	for _, tt := range tests {
		if got := Label(tt.entropy); got != tt.want {
			t.Errorf("Label(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}

func TestLabelNormal(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{2.5, "normal"},
		{3.0, "normal"},
		{3.99, "normal"},
	}
	for _, tt := range tests {
		if got := Label(tt.entropy); got != tt.want {
			t.Errorf("Label(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}

func TestLabelElevated(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{4.0, "elevated"},
		{4.5, "elevated"},
		{4.99, "elevated"},
	}
	for _, tt := range tests {
		if got := Label(tt.entropy); got != tt.want {
			t.Errorf("Label(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}

func TestLabelHigh(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{5.0, "high"},
		{5.25, "high"},
		{5.49, "high"},
	}
	for _, tt := range tests {
		if got := Label(tt.entropy); got != tt.want {
			t.Errorf("Label(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}

func TestLabelVeryHigh(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{5.5, "very high"},
		{6.0, "very high"},
		{8.0, "very high"},
	}
	for _, tt := range tests {
		if got := Label(tt.entropy); got != tt.want {
			t.Errorf("Label(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}
