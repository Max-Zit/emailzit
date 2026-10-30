package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/backup"
)

// Backups of the console itself: the database with the secret key and the
// console certificate, written to data-dir/backups on a schedule (and on
// request), always encrypted with the backup passphrase, optionally copied
// to an SFTP folder. The vaults in it stay end-to-end encrypted; the
// passphrase protects the server secrets (2FA secrets, sessions). A
// restore runs with the server stopped (emailzit-server -restore, or the
// appliance setup menu).

const (
	settingBackup = "backup"
	backupPrefix  = "emailzit-backup-"
	sealBackupKey = "settings.backup.passphrase"
	sealSFTPPass  = "settings.backup.sftp.password"
	sealSFTPKey   = "settings.backup.sftp.key"
)

// BackupSettings control the console backups. The passphrase and the SFTP
// password and key are sealed with the server's secret key.
type BackupSettings struct {
	Enabled    bool   `json:"enabled"`
	Hour       int    `json:"hour"`
	Keep       int    `json:"keep"`
	Passphrase string `json:"passphrase,omitempty"`
	SFTP       struct {
		Enabled  bool   `json:"enabled"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password,omitempty"`
		Key      string `json:"key,omitempty"`
		Dir      string `json:"dir"`
		HostKey  string `json:"host_key"`
	} `json:"sftp"`
	LastRun   time.Time `json:"last_run"`
	LastOK    bool      `json:"last_ok"`
	LastError string    `json:"last_error,omitempty"`
	LastFile  string    `json:"last_file,omitempty"`
	LastSize  int64     `json:"last_size,omitempty"`
	LastCopy  string    `json:"last_copy,omitempty"` // SFTP result of the last backup
}

func (s *Server) backupSettings(ctx context.Context) BackupSettings {
	b := BackupSettings{Hour: 2, Keep: 7}
	_ = s.store.GetSetting(ctx, settingBackup, &b)
	if b.Keep < 1 {
		b.Keep = 7
	}
	return b
}

// backupRunner allows one backup at a time.
type backupRunner struct {
	mu      sync.Mutex
	running bool
}

func (s *Server) backupDir() string { return filepath.Join(s.DataDir, "backups") }

// RunBackups starts the scheduled backup once a day at the set hour.
func (s *Server) RunBackups(ctx context.Context) {
	if s.DataDir == "" {
		return
	}
	b := s.backupSettings(ctx)
	now := s.now().Local()
	if !b.Enabled || now.Hour() != b.Hour {
		return
	}
	if last := b.LastRun.Local(); last.Year() == now.Year() && last.YearDay() == now.YearDay() {
		return
	}
	s.startBackup("system")
}

// startBackup runs a backup in the background; false when one runs.
func (s *Server) startBackup(by string) bool {
	s.backups.mu.Lock()
	if s.backups.running {
		s.backups.mu.Unlock()
		return false
	}
	s.backups.running = true
	s.backups.mu.Unlock()
	go func() { // #nosec G118 -- a backup outlives the request or tick that started it
		defer func() {
			s.backups.mu.Lock()
			s.backups.running = false
			s.backups.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		s.runBackup(ctx, by)
	}()
	return true
}

func (s *Server) backupRunning() bool {
	s.backups.mu.Lock()
	defer s.backups.mu.Unlock()
	return s.backups.running
}

// runBackup writes one backup, prunes the old ones, copies it to SFTP and
// records the outcome (audit log; an alert email when it fails).
func (s *Server) runBackup(ctx context.Context, by string) {
	b := s.backupSettings(ctx)
	start := s.now()
	name, size, err := s.writeBackup(ctx, b, start)
	b.LastRun, b.LastOK, b.LastError, b.LastCopy = start, err == nil, "", ""
	if err != nil {
		b.LastError = clip(err.Error(), 500)
	} else {
		b.LastFile, b.LastSize = name, size
		s.pruneBackups(b.Keep)
		if b.SFTP.Enabled {
			if cerr := s.copyBackup(ctx, b, name); cerr != nil {
				b.LastOK, b.LastCopy = false, clip("SFTP: "+cerr.Error(), 500)
			} else {
				b.LastCopy = "ok"
			}
		}
	}
	fresh := s.backupSettings(ctx) // keep settings saved meanwhile
	fresh.LastRun, fresh.LastOK, fresh.LastError, fresh.LastFile, fresh.LastSize, fresh.LastCopy = b.LastRun, b.LastOK, b.LastError, b.LastFile, b.LastSize, b.LastCopy
	_ = s.store.SetSetting(ctx, settingBackup, fresh)
	switch {
	case err != nil:
		s.log.Error("console backup failed", "err", err)
		_ = s.store.Audit(ctx, by, "", "backup.failed", "settings", "console backup failed: "+b.LastError)
	case b.LastCopy != "" && b.LastCopy != "ok":
		_ = s.store.Audit(ctx, by, "", "backup.create", "settings", "console backup "+name+" ("+formatBytes(uint64(size))+"); copy failed: "+b.LastCopy) // #nosec G115 -- a file size
	default:
		_ = s.store.Audit(ctx, by, "", "backup.create", "settings", "console backup "+name+" ("+formatBytes(uint64(size))+")") // #nosec G115 -- a file size
	}
}

// writeBackup writes the backup file through a temporary name.
func (s *Server) writeBackup(ctx context.Context, b BackupSettings, at time.Time) (string, int64, error) {
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	if b.Passphrase == "" {
		return "", 0, errors.New("set a backup passphrase first: backups are always encrypted")
	}
	pass, err := s.store.OpenSecret(sealBackupKey, b.Passphrase)
	if err != nil {
		return "", 0, errors.New("the backup passphrase cannot be read; set it again")
	}
	name := backupPrefix + at.Local().Format("20060102-150405") + backup.Ext
	tmp := filepath.Join(dir, name+".part")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- our own folder and name
	if err != nil {
		return "", 0, err
	}
	_, err = backup.Create(ctx, s.store, s.DataDir, dir, s.Version, pass, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", 0, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return "", 0, err
	}
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return "", 0, err
	}
	return name, st.Size(), nil
}

// backupFile is a backup in the local folder.
type backupFile struct {
	Name      string
	Size      uint64
	At        time.Time
	Encrypted bool
}

// localBackups lists the backups, newest first.
func (s *Server) localBackups() []backupFile {
	ents, err := os.ReadDir(s.backupDir())
	if err != nil {
		return nil
	}
	var out []backupFile
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(n, backupPrefix) || !strings.HasSuffix(n, backup.Ext) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		bf := backupFile{Name: n, Size: uint64(info.Size()), At: info.ModTime()} // #nosec G115 -- a file size
		if f, err := os.Open(filepath.Join(s.backupDir(), n)); err == nil {      // #nosec G304 -- our own folder
			head := make([]byte, 7)
			_, _ = io.ReadFull(f, head)
			bf.Encrypted = backup.IsEncrypted(head)
			_ = f.Close()
		}
		out = append(out, bf)
	}
	slices.SortFunc(out, func(a, b backupFile) int { return strings.Compare(b.Name, a.Name) })
	return out
}

// pruneBackups keeps the newest keep backups (and removes left-over parts).
func (s *Server) pruneBackups(keep int) {
	list := s.localBackups()
	for i := keep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(s.backupDir(), list[i].Name))
	}
	if ents, err := os.ReadDir(s.backupDir()); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".part") || strings.HasSuffix(e.Name(), ".tmp") {
				if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 7*time.Hour {
					_ = os.Remove(filepath.Join(s.backupDir(), e.Name()))
				}
			}
		}
	}
}

// sftpOf opens the sealed SFTP secrets of the settings.
func (s *Server) sftpOf(b BackupSettings) (backup.SFTP, error) {
	c := backup.SFTP{Host: b.SFTP.Host, Port: b.SFTP.Port, User: b.SFTP.User, Dir: b.SFTP.Dir, HostKey: b.SFTP.HostKey}
	var err error
	if b.SFTP.Password != "" {
		if c.Password, err = s.store.OpenSecret(sealSFTPPass, b.SFTP.Password); err != nil {
			return c, uiMsg("The SFTP password cannot be read; set it again.")
		}
	}
	if b.SFTP.Key != "" {
		if c.Key, err = s.store.OpenSecret(sealSFTPKey, b.SFTP.Key); err != nil {
			return c, uiMsg("The SFTP key cannot be read; set it again.")
		}
	}
	return c, nil
}

func (s *Server) copyBackup(ctx context.Context, b BackupSettings, name string) error {
	c, err := s.sftpOf(b)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(s.backupDir(), name)) // #nosec G304 -- our own folder and name
	if err != nil {
		return err
	}
	defer f.Close()
	return backup.UploadSFTP(ctx, c, name, backupPrefix, b.Keep, f)
}

// ---- pages

type backupData struct {
	S       BackupSettings
	Files   []backupFile
	Hours   []int
	Running bool
	HasPass bool
	HasPw   bool
	HasKey  bool
}

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	b := s.backupSettings(r.Context())
	hours := make([]int, 24)
	for i := range hours {
		hours[i] = i
	}
	d := &backupData{S: b, Files: s.localBackups(), Hours: hours, Running: s.backupRunning(),
		HasPass: b.Passphrase != "", HasPw: b.SFTP.Password != "", HasKey: b.SFTP.Key != ""}
	d.S.Passphrase, d.S.SFTP.Password, d.S.SFTP.Key = "", "", ""
	s.render(w, r, http.StatusOK, "backup", &Page{Title: "Backup of the panel", Nav: "settings", Data: d})
}

func (s *Server) handleBackupSave(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/backup"
	b := s.backupSettings(r.Context())
	b.Enabled = r.FormValue("enabled") == "1"
	b.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	b.Keep, _ = strconv.Atoi(r.FormValue("keep"))
	if b.Hour < 0 || b.Hour > 23 || b.Keep < 1 || b.Keep > 90 {
		s.redirectErr(w, r, back, "Keep 1–90 backups.")
		return
	}
	switch p := r.FormValue("passphrase"); {
	case p != "":
		if len(p) < 12 {
			s.redirectErr(w, r, back, "The passphrase needs at least 12 characters.")
			return
		}
		if p != r.FormValue("passphrase2") {
			s.redirectErr(w, r, back, "The passphrases do not match.")
			return
		}
		b.Passphrase = s.store.SealSecret(sealBackupKey, p)
	}
	b.SFTP.Enabled = r.FormValue("sftp_enabled") == "1"
	host := strings.TrimSpace(r.FormValue("sftp_host"))
	if host != b.SFTP.Host {
		b.SFTP.HostKey = "" // another server: trust its key again
	}
	b.SFTP.Host = host
	b.SFTP.Port, _ = strconv.Atoi(r.FormValue("sftp_port"))
	b.SFTP.User = strings.TrimSpace(r.FormValue("sftp_user"))
	b.SFTP.Dir = strings.TrimSpace(r.FormValue("sftp_dir"))
	if pw := r.FormValue("sftp_password"); pw != "" {
		b.SFTP.Password = s.store.SealSecret(sealSFTPPass, pw)
	} else if r.FormValue("sftp_password_clear") == "1" {
		b.SFTP.Password = ""
	}
	if k := strings.TrimSpace(r.FormValue("sftp_key")); k != "" {
		b.SFTP.Key = s.store.SealSecret(sealSFTPKey, k+"\n")
	} else if r.FormValue("sftp_key_clear") == "1" {
		b.SFTP.Key = ""
	}
	if b.SFTP.Port == 0 {
		b.SFTP.Port = 22
	}
	if b.SFTP.Enabled && (b.SFTP.Host == "" || b.SFTP.User == "" || (b.SFTP.Password == "" && b.SFTP.Key == "") || b.SFTP.Port < 1 || b.SFTP.Port > 65535) {
		s.redirectErr(w, r, back, "The SFTP copy needs a server, a user and a password or key.")
		return
	}
	if strings.ContainsAny(b.SFTP.Host+b.SFTP.User+b.SFTP.Dir, "\r\n\x00") {
		s.redirectErr(w, r, back, "Unknown action.")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingBackup, b); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.backup", "settings",
		"console backup: daily %v at %02d:00, keep %d, encrypted %v, SFTP %v %s", b.Enabled, b.Hour, b.Keep, b.Passphrase != "", b.SFTP.Enabled, b.SFTP.Host)
	if b.SFTP.Enabled && b.SFTP.HostKey == "" {
		s.redirect(w, r, back, "Saved. Test the SFTP connection to trust the server's key.")
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if !s.startBackup(userFrom(r).Username) {
		s.redirectErr(w, r, "/settings/backup", "A backup is running already.")
		return
	}
	s.redirect(w, r, "/settings/backup", "The backup runs; this page shows the result when it is done.")
}

// handleBackupTest connects to the SFTP folder; the first successful test
// trusts the server's host key (the administrator sees its fingerprint).
func (s *Server) handleBackupTest(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/backup"
	b := s.backupSettings(r.Context())
	c, err := s.sftpOf(b)
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if c.Host == "" {
		s.redirectErr(w, r, back, "Save the SFTP server first.")
		return
	}
	trust := r.FormValue("trust") == "1"
	if trust {
		c.HostKey = r.FormValue("fingerprint")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	fp, err := backup.TestSFTP(ctx, c)
	var hk *backup.ErrHostKey
	switch {
	case errors.As(err, &hk) && b.SFTP.HostKey == "" && !trust:
		s.render(w, r, http.StatusOK, "backuptrust", &Page{Title: "Backup of the panel", Nav: "settings", Data: map[string]string{"Host": c.Host, "Fingerprint": hk.Fingerprint}})
		return
	case err != nil:
		s.redirectErr(w, r, back, fmt.Sprintf(translate(s.lang(r, userFrom(r)), "SFTP test failed: %s"), err))
		return
	}
	if b.SFTP.HostKey != fp {
		b.SFTP.HostKey = fp
		if err := s.store.SetSetting(r.Context(), settingBackup, b); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "settings.backup", "settings", "trusted the SFTP host key %s of %s", fp, c.Host)
	}
	s.redirect(w, r, back, "The SFTP folder works.")
}

// backupByName finds a local backup by its name (only names from the list).
func (s *Server) backupByName(name string) *backupFile {
	for _, f := range s.localBackups() {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	f := s.backupByName(r.PathValue("name"))
	if f == nil {
		s.notFound(w, r)
		return
	}
	file, err := os.Open(filepath.Join(s.backupDir(), f.Name)) // #nosec G304 -- a name from our own list
	if err != nil {
		s.notFound(w, r)
		return
	}
	defer file.Close()
	s.audit(r, "backup.download", "settings", "downloaded the console backup %s", f.Name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	w.Header().Set("Content-Length", strconv.FormatUint(f.Size, 10))
	_, _ = io.Copy(w, file)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	f := s.backupByName(r.FormValue("name"))
	if f == nil {
		s.redirectErr(w, r, "/settings/backup", "Unknown action.")
		return
	}
	if err := os.Remove(filepath.Join(s.backupDir(), f.Name)); err != nil {
		s.redirectErr(w, r, "/settings/backup", err.Error())
		return
	}
	s.audit(r, "backup.delete", "settings", "deleted the console backup %s", f.Name)
	s.redirect(w, r, "/settings/backup", "Deleted.")
}

// LastBytes is the size of the last backup, for the page.
func (b BackupSettings) LastBytes() uint64 { return uint64(max(b.LastSize, 0)) } // #nosec G115 -- non-negative

// clip shortens a message for the settings (at a character boundary).
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Bytes formats a size for the pages.
func (p *Page) Bytes(n uint64) string { return formatBytes(n) }

// uiMsg is an error whose text is a sentence for the user (translated when shown).
type uiMsg string

func (m uiMsg) Error() string { return string(m) }
