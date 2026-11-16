package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// The write of the mail configuration at start is interrupted when the
// package restarts this service while it runs. It has to be written again,
// or the server stays without /etc/postfix/main.cf and no mail flows until
// an administrator saves the mail settings (found on a fresh appliance,
// 2026-11-15).
func TestTheMailConfigurationIsWrittenAgainAfterAnInterruptedTry(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	old := mailConfigRetry
	mailConfigRetry = 5 * time.Millisecond
	t.Cleanup(func() { mailConfigRetry = old })
	t.Run("a lost write is made good", func(t *testing.T) {
		tries := 0
		err := startMailConfig(context.Background(), quiet, func(context.Context) error {
			tries++
			if tries < 3 {
				return errors.New("postfix: signal: terminated")
			}
			return nil
		})
		if err != nil || tries != 3 {
			t.Fatalf("%d tries, err %v", tries, err)
		}
	})
	t.Run("a write that never works is given up on", func(t *testing.T) {
		tries := 0
		want := errors.New("no")
		err := startMailConfig(context.Background(), quiet, func(context.Context) error {
			tries++
			return want
		})
		if !errors.Is(err, want) || tries != mailConfigTries {
			t.Fatalf("%d tries, err %v", tries, err)
		}
	})
	t.Run("a stopping service does not wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		tries := 0
		start := time.Now()
		if err := startMailConfig(ctx, quiet, func(context.Context) error {
			tries++
			return errors.New("terminated")
		}); err == nil {
			t.Fatal("the error of the last try is kept")
		}
		if tries != 1 || time.Since(start) > time.Second {
			t.Fatalf("%d tries in %s", tries, time.Since(start))
		}
	})
}
