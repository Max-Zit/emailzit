package mailhelper

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// keepExports is how many exports of a customer are kept.
const keepExports = 3

// export packs a customer's mail (/var/vmail/<customer>) and the manifest
// the panel sends (settings, no secrets) into
// /var/lib/emailzit/exports/<customer>/<name>.tar.gz for the panel user.
func (s *Server) export(ctx context.Context, r Request) (*ExportResult, error) {
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM customers WHERE id=$1`, r.Customer).Scan(&n); err != nil || n != 1 {
		return nil, errors.New("unknown customer")
	}
	dir := filepath.Join(ExportDir, r.Customer)
	for _, d := range []string{ExportDir, dir} {
		if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		st, err := os.Lstat(d)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is not a directory", d)
		}
		if err := os.Chown(d, s.AllowUID, -1); err != nil {
			return nil, err
		}
	}
	final := filepath.Join(dir, r.Name+".tar.gz")
	part := final + ".part"
	_ = os.Remove(part)
	// #nosec G304 -- name validated (digits and a dash), directory checked above
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(part)
		}
	}()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	now := time.Now()
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(r.Manifest)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(tw, r.Manifest); err != nil {
		return nil, err
	}
	res := &ExportResult{File: r.Name + ".tar.gz"}
	// os.Root: nothing below the customer's directory can lead out of it,
	// not even a directory swapped for a link while the walk runs
	if root, err := os.OpenRoot(filepath.Join(s.VMail, r.Customer)); err == nil {
		defer root.Close()
		err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if p == "." {
				return nil
			}
			name := "mail/" + p
			info, err := d.Info()
			if err != nil {
				return nil // gone meanwhile (new mail moved by Dovecot)
			}
			switch {
			case d.IsDir():
				return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, ModTime: info.ModTime(), Typeflag: tar.TypeDir})
			case !info.Mode().IsRegular():
				return nil // never follow or store links
			}
			src, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return nil
			}
			defer src.Close()
			st, err := src.Stat()
			if err != nil || !st.Mode().IsRegular() {
				return nil
			}
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
				return err
			}
			// a file that shrinks while it is read (a Dovecot index) is padded
			n, err := io.CopyN(tw, src, st.Size())
			if errors.Is(err, io.EOF) {
				_, err = io.CopyN(tw, zeros{}, st.Size()-n)
			}
			if err != nil {
				return err
			}
			res.Files++
			res.MailBytes += st.Size()
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := f.Chown(s.AllowUID, -1); err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(part, final); err != nil {
		return nil, err
	}
	ok = true
	res.Size = st.Size()
	pruneExports(dir)
	return res, nil
}

// pruneExports keeps the newest exports of a customer.
func pruneExports(dir string) {
	names, _ := filepath.Glob(filepath.Join(dir, "*.tar.gz"))
	sort.Strings(names) // names are times: oldest first
	for len(names) > keepExports {
		_ = os.Remove(names[0])
		names = names[1:]
	}
}

// status reports the health of the mail system (WatchZit).
func (s *Server) status(ctx context.Context) *Status {
	st := &Status{Services: map[string]string{}}
	for _, u := range []string{"postfix", "dovecot", "rspamd", "valkey-server", "emailzit-submit.socket"} {
		out, _ := s.Run(ctx, "systemctl", "is-active", u)
		st.Services[strings.TrimSuffix(u, ".socket")] = strings.TrimSpace(string(out))
	}
	if out, err := s.Run(ctx, "postqueue", "-j"); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "{") {
				st.Queue++
				var q struct {
					Status string `json:"queue_name"`
				}
				if json.Unmarshal([]byte(l), &q) == nil && q.Status == "deferred" {
					st.Deferred++
				}
			}
		}
	}
	var fsst syscall.Statfs_t
	if syscall.Statfs(s.VMail, &fsst) == nil {
		bs := uint64(max(fsst.Bsize, 0))
		// #nosec G115 -- megabytes of a file system fit easily
		st.DiskTotalMB, st.DiskFreeMB = int64(fsst.Blocks*bs>>20), int64(fsst.Bavail*bs>>20)
	}
	if b, err := os.ReadFile(s.CertFile); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				t := c.NotAfter
				st.CertNotAfter = &t
			}
		}
	}
	return st
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
