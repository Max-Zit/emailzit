//go:build !linux

package mailhelper

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Server is the helper service; it runs on Linux only.
type Server struct {
	Log                                      *slog.Logger
	DB                                       *pgxpool.Pool
	DBName, CertFile, KeyFile, Relay, Policy string
	VMail                                    string
	AllowUID                                 int
	Run                                      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Serve is not available on this system.
func (s *Server) Serve(ctx context.Context, path string) error {
	return errors.New("the mail helper runs on Linux only")
}

// Start is not available on this system.
func (s *Server) Start(ctx context.Context, r Request) error { return s.Serve(ctx, "") }

// EnsureCustomerDirs is not available on this system.
func (s *Server) EnsureCustomerDirs(ctx context.Context) error { return nil }

// PolicyDir is where the policy socket lives (Linux).
const PolicyDir = "/var/spool/postfix/emailzit"

// PeerUID is not available on this system.
func PeerUID(c net.Conn) (int, error) { return -1, errors.New("not supported") }

// PostfixUID is not available on this system.
func PostfixUID() int { return -1 }
