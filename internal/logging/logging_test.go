package logging

import (
	"log/slog"
	"testing"
)

// TestParseLevel verifies level name conversion.
func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"trace", slog.LevelDebug, false},
		{"debug", slog.LevelDebug, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"fatal", 0, true},
	}

	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseLevel(%q) error = %v, wantErr = %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseSize verifies byte size parsing with suffixes.
func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"5MB", 5 << 20, false},
		{"1KB", 1 << 10, false},
		{"2GB", 2 << 30, false},
		{"1024", 1024, false},
		{" 3 MB ", 3 << 20, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-5MB", 0, true},
	}

	for _, tc := range cases {
		got, err := ParseSize(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseSize(%q) error = %v, wantErr = %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
