package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Only a web server on THIS machine may hold the ports 80 and 443. A
// linked HostZit must not count: it can run on another server, and then
// nothing would answer for MTA-STS, autoconfig and Autodiscover here.
func TestPortsTakenOnlyByAWebServerOfThisMachine(t *testing.T) {
	dir := t.TempDir()
	nginx := filepath.Join(dir, "nginx")
	old := webServers
	webServers = []string{nginx}
	t.Cleanup(func() { webServers = old })

	if why := portsTaken(); why != "" {
		t.Errorf("no web server installed, but the ports are left to %q", why)
	}
	if err := os.WriteFile(nginx, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a stand-in for a program
		t.Fatal(err)
	}
	if why := portsTaken(); why == "" {
		t.Error("a web server is installed, but the ports are not left to it")
	}
	if err := os.Remove(nginx); err != nil {
		t.Fatal(err)
	}
	if why := portsTaken(); why != "" {
		t.Errorf("the web server is gone, but the ports are still left to %q", why)
	}
}
