package mtasts

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

const good = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.backup.example.net\nmax_age: 86400\n"

func TestParse(t *testing.T) {
	p, err := Parse([]byte(strings.ReplaceAll(good, "\n", "\r\n")))
	if err != nil || p.Mode != "enforce" || len(p.MX) != 2 || p.MaxAge != 24*time.Hour {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"mode: enforce\nmx: a.example\n", "version: STSv1\nmode: strict\nmx: a.example\n", "version: STSv1\nmode: enforce\n",
		"version: STSv1\nmode: enforce\nmx: a.*.example\n", "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAnswerAndCache(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	id, fetches, txtErr := "1", 0, error(nil)
	s := &Service{AllowUID: -1, Now: func() time.Time { return now },
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name != "_mta-sts.example.com" {
				return nil, &net.DNSError{IsNotFound: true}
			}
			return []string{"v=STSv1; id=" + id}, txtErr
		},
		Fetch: func(context.Context, string) ([]byte, error) { fetches++; return []byte(good), nil }}
	ctx := context.Background()
	if a := s.Answer(ctx, "Example.com."); a != "OK secure match=mx1.example.com:.backup.example.net" {
		t.Fatalf("answer %q", a)
	}
	if a := s.Answer(ctx, "other.example"); a != "NOTFOUND " {
		t.Fatalf("no policy: %q", a)
	}
	s.Answer(ctx, "example.com")
	if fetches != 1 {
		t.Fatalf("fetched %d times", fetches)
	}
	// a new id after the TXT check interval: fetched again
	now, id = now.Add(2*time.Hour), "2"
	s.Answer(ctx, "example.com")
	if fetches != 2 {
		t.Fatalf("new id not fetched (%d)", fetches)
	}
	// DNS failing: the cached policy keeps applying
	now, txtErr = now.Add(2*time.Hour), errors.New("timeout")
	if a := s.Answer(ctx, "example.com"); !strings.HasPrefix(a, "OK secure") {
		t.Fatalf("cached policy lost: %q", a)
	}
	// DANE wins where it works
	s.HasTLSA = func(context.Context, string) bool { return true }
	s.LookupMX = func(context.Context, string) ([]string, error) { return []string{"mx1.example.com"}, nil }
	if a := s.Answer(ctx, "example.com"); a != "NOTFOUND " {
		t.Fatalf("DANE domain: %q", a)
	}
}

func TestSocketmap(t *testing.T) {
	s := &Service{AllowUID: -1, LookupTXT: func(context.Context, string) ([]string, error) { return nil, &net.DNSError{IsNotFound: true} }}
	a, b := net.Pipe()
	go s.conn(context.Background(), a)
	if _, err := b.Write([]byte("18:mtasts example.org,7:bad req,")); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(b)
	for _, want := range []string{"NOTFOUND ", "PERM invalid request"} {
		got, err := readNetstring(r)
		if err != nil || got != want {
			t.Fatalf("got %q %v, want %q", got, err, want)
		}
	}
	b.Close()
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(good))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err == nil && p.Mode == "enforce" && len(p.MX) == 0 {
			t.Fatal("enforce without mx")
		}
	})
}

func FuzzNetstring(f *testing.F) {
	f.Add([]byte("18:mtasts example.org,"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readNetstring(bufio.NewReader(strings.NewReader(string(b))))
	})
}
