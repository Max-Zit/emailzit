package web

// The mail of the customers in the nightly backup.
//
// The console backup holds the database, the keys and the settings — not
// one message. The mail itself lives in /var/vmail, and until now the
// only copy of it was whatever the operator arranged outside EmailZit
// (BackupZit over the whole folder, or the export of a single customer by
// hand). For a small server that is one step too many, and a mail server
// without a copy of the mail is a mail server waiting for a dead disk.
//
// So the nightly run can also export every active customer and put the
// export next to the console backup on the SFTP target, sealed with the
// same passphrase. Nothing new is invented: the export is the one the
// customer page writes, and the import on the customer page reads it back
// — including a sealed file, so a restore needs nothing but the panel and
// the passphrase.
//
// It writes a FULL copy of every customer each night. That is honest for
// a server with a few gigabytes of mail and wrong for a big one, which is
// why it is off by default and the page says so.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/backup"
	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// MailBackup says whether the nightly run also copies the mail of the
// customers, and how many copies of each customer stay on the target.
type MailBackup struct {
	Enabled bool `json:"enabled,omitempty"`
	Keep    int  `json:"keep,omitempty"`
	// Last* describe the last run.
	LastRun       time.Time `json:"last_run,omitempty"`
	LastCustomers int       `json:"last_customers,omitempty"`
	LastBytes     int64     `json:"last_bytes,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

// mailBackupPrefix starts the name of a mail backup on the target:
// mail-<customer>-<time>.ezm. The customer is part of the prefix, so the
// pruning of one customer never touches another.
const mailBackupPrefix = "mail-"

// mailBackupName is the file name of one customer's backup.
func mailBackupName(customerID string, at time.Time) string {
	return mailBackupPrefix + customerID + "-" + at.UTC().Format("20060102-150405") + ".ezm"
}

// runMailBackup exports every active customer and copies the export to
// the SFTP target, sealed with the backup passphrase. It returns what to
// write into the settings.
func (s *Server) runMailBackup(ctx context.Context, b BackupSettings, by string) MailBackup {
	out := MailBackup{Enabled: true, Keep: b.Mail.Keep, LastRun: s.now()}
	pass, err := s.backupPassphrase(b)
	if err != nil {
		out.LastError = clip(err.Error(), 300)
		return out
	}
	if !b.SFTP.Enabled {
		out.LastError = "no SFTP target: the exports stay on this server"
	}
	cs, err := s.store.Customers(ctx, store.CustomerFilter{Limit: 500})
	if err != nil {
		out.LastError = clip(err.Error(), 300)
		return out
	}
	var failed []string
	for _, c := range cs {
		if ctx.Err() != nil {
			break
		}
		if c.Status == store.CustomerTerminated {
			continue
		}
		size, err := s.backupCustomerMail(ctx, b, pass, c, by)
		if err != nil {
			s.log.Error("mail backup of a customer", "customer", c.ID, "err", err)
			failed = append(failed, c.Name)
			continue
		}
		out.LastCustomers++
		out.LastBytes += size
	}
	if len(failed) > 0 {
		out.LastError = clip(fmt.Sprintf("%d of %d customers failed: %s", len(failed), len(cs), strings.Join(failed, ", ")), 300)
	}
	return out
}

// backupCustomerMail exports one customer and copies the export sealed.
func (s *Server) backupCustomerMail(ctx context.Context, b BackupSettings, pass string, c *store.Customer, by string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, mailhelper.ExportTimeout)
	defer cancel()
	res, err := s.runExport(ctx, c, by)
	if err != nil {
		return 0, err
	}
	if !b.SFTP.Enabled {
		return res.Size, nil // the export on this server is all there is
	}
	sftp, err := s.sftpOf(b)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(filepath.Join(s.exportDir(c.ID), res.File)) // #nosec G304 -- our own folder, name from the helper
	if err != nil {
		return 0, err
	}
	defer f.Close()
	pr, pw := io.Pipe()
	go func() {
		w, err := backup.Seal(pw, pass)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(w, f); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.CloseWithError(w.Close())
	}()
	name := mailBackupName(c.ID, s.now())
	if err := backup.UploadSFTP(ctx, sftp, name, mailBackupPrefix+c.ID+"-", max(b.Mail.Keep, 1), pr); err != nil {
		return 0, err
	}
	return res.Size, nil
}

// backupPassphrase opens the sealed passphrase of the backups.
func (s *Server) backupPassphrase(b BackupSettings) (string, error) {
	if b.Passphrase == "" {
		return "", uiMsg("Set a passphrase for the backups first.")
	}
	pass, err := s.store.OpenSecret(sealBackupKey, b.Passphrase)
	if err != nil {
		return "", uiMsg("The passphrase of the backups cannot be read; set it again.")
	}
	return pass, nil
}
