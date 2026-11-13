package helper_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPackageFileModes: every file in the deb states its mode. nfpm on
// Windows gives 0664 to a file without file_info, and tools such as
// logrotate and systemd refuse a group-writable file.
func TestPackageFileModes(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "linux", "nfpm-server.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dst string
	mode := regexp.MustCompile(`^\s+mode: 0[0-7]{3}$`)
	seen := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "  - src:"):
			if dst != "" && !seen {
				t.Errorf("%s has no file_info mode", dst)
			}
			dst, seen = "", false
		case strings.HasPrefix(line, "    dst:"):
			dst = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "dst:"))
		case mode.MatchString(line):
			seen = true
		}
	}
	if dst != "" && !seen {
		t.Errorf("%s has no file_info mode", dst)
	}
}
