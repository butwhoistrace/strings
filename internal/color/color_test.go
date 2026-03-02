package color

import "testing"

func TestApplyEnabled(t *testing.T) {
	c := &Colorizer{Enabled: true}
	got := c.Apply("test", "red")
	if got == "test" {
		t.Error("expected colored output when enabled")
	}
	if got != "\033[91mtest\033[0m" {
		t.Errorf("unexpected color output: %q", got)
	}
}

func TestApplyDisabled(t *testing.T) {
	c := &Colorizer{Enabled: false}
	got := c.Apply("test", "red")
	if got != "test" {
		t.Errorf("expected plain text when disabled, got %q", got)
	}
}

func TestApplyUnknownColor(t *testing.T) {
	c := &Colorizer{Enabled: true}
	got := c.Apply("test", "nonexistent")
	if got != "test" {
		t.Errorf("expected plain text for unknown color, got %q", got)
	}
}

func TestApplyAllColors(t *testing.T) {
	c := &Colorizer{Enabled: true}
	colors := []string{"reset", "bold", "dim", "red", "green", "yellow", "blue", "magenta", "cyan", "white", "gray"}
	for _, name := range colors {
		got := c.Apply("x", name)
		if got == "x" {
			t.Errorf("color %q should produce colored output", name)
		}
	}
}

func TestCategoryColor(t *testing.T) {
	tests := map[string]string{
		"url":          "blue",
		"email":        "cyan",
		"credential":   "red",
		"general":      "gray",
		"nonexistent":  "gray",
	}
	for cat, want := range tests {
		got := CategoryColor(cat)
		if got != want {
			t.Errorf("CategoryColor(%q) = %q, want %q", cat, got, want)
		}
	}
}
