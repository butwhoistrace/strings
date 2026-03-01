package entropy

import (
	"math"
	"unicode/utf8"
)

func Calculate(s string) float64 {
	runeCount := utf8.RuneCountInString(s)
	if runeCount <= 1 {
		return 0.0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(runeCount)
	result := 0.0
	for _, count := range freq {
		p := float64(count) / length
		result -= p * math.Log2(p)
	}
	return math.Round(result*100) / 100
}

func Label(e float64) string {
	switch {
	case e < 2.5:
		return "low"
	case e < 4.0:
		return "normal"
	case e < 5.0:
		return "elevated"
	case e < 5.5:
		return "high"
	default:
		return "very high"
	}
}
