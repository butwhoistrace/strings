package entropy

import "math"

func Calculate(s string) float64 {
	if len(s) <= 1 {
		return 0.0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	result := 0.0
	for _, count := range freq {
		p := float64(count) / length
		result -= p * math.Log2(p)
	}
	return result
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
