package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SFTP is a remote folder for backup copies. HostKey is the SHA256
// fingerprint of the server's host key (as ssh-keygen -l prints it); a
// connection to a server with another key fails.
type SFTP struct {
	Host     string
	Port     int
	User     string
	Password string
	Key      string // private key (PEM/OpenSSH), instead of or with the password
	Dir      string
	HostKey  string
}

// ErrHostKey is returned when the server's host key is not the expected one;
// Fingerprint names the key the server showed.
type ErrHostKey struct{ Fingerprint string }

func (e *ErrHostKey) Error() string {
	return "the SFTP server's host key " + e.Fingerprint + " is not the trusted one"
}

// sftpClient speaks the SFTP protocol version 3 over one SSH channel, one
// request after another (writes are pipelined).
type sftpClient struct {
	conn *ssh.Client
	sess *ssh.Session
	in   io.WriteCloser
	out  io.Reader
	id   uint32
	stop func() bool
}

const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpWrite    = 6
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRename   = 18
	fxpStatus   = 101
	fxpHandle   = 102
	fxpName     = 104
	fxOK        = 0
	fxEOF       = 1
	openWrite   = 0x02
	openCreate  = 0x08
	openTrunc   = 0x10
	sftpChunk   = 32 << 10
	sftpWindow  = 16 // writes in flight
	maxResponse = 1 << 20
)

// dialSFTP connects and starts the sftp subsystem. seen receives the host
// key fingerprint the server showed (also when it is rejected).
func dialSFTP(ctx context.Context, c SFTP, seen *string) (*sftpClient, error) {
	var auth []ssh.AuthMethod
	if c.Key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.Key))
		if err != nil {
			return nil, errors.New("the private key cannot be read (it must not have a passphrase)")
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}
	port := c.Port
	if port == 0 {
		port = 22
	}
	cfg := &ssh.ClientConfig{User: c.User, Auth: auth, Timeout: 20 * time.Second,
		// The ed25519 key first: the page asks to compare it with ssh_host_ed25519_key.pub.
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if seen != nil {
				*seen = fp
			}
			if c.HostKey == "" || fp != c.HostKey {
				return &ErrHostKey{Fingerprint: fp}
			}
			return nil
		}}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	d := net.Dialer{Timeout: 20 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		var hk *ErrHostKey
		if errors.As(err, &hk) {
			return nil, hk
		}
		return nil, err
	}
	conn := ssh.NewClient(sc, chans, reqs)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // a cancelled backup ends the connection
	sess, err := conn.NewSession()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	in, err := sess.StdinPipe()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		_ = conn.Close()
		return nil, errors.New("the server does not offer SFTP")
	}
	cl := &sftpClient{conn: conn, sess: sess, in: in, out: out, stop: stop}
	var p []byte
	p = binary.BigEndian.AppendUint32(p, 3)
	if err := cl.send(fxpInit, p); err != nil {
		cl.Close()
		return nil, err
	}
	typ, _, err := cl.recv()
	if err != nil || typ != fxpVersion {
		cl.Close()
		return nil, errors.New("the SFTP server did not answer")
	}
	return cl, nil
}

func (c *sftpClient) Close() {
	c.stop()
	_ = c.in.Close()
	_ = c.sess.Close()
	_ = c.conn.Close()
}

func (c *sftpClient) send(typ byte, payload []byte) error {
	var h [5]byte
	binary.BigEndian.PutUint32(h[:4], uint32(len(payload)+1)) // #nosec G115 -- small packets
	h[4] = typ
	if _, err := c.in.Write(h[:]); err != nil {
		return err
	}
	_, err := c.in.Write(payload)
	return err
}

func (c *sftpClient) recv() (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c.out, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n < 1 || n > maxResponse {
		return 0, nil, errors.New("SFTP: bad response")
	}
	p := make([]byte, n-1)
	if _, err := io.ReadFull(c.out, p); err != nil {
		return 0, nil, err
	}
	return h[4], p, nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- short strings
	return append(b, s...)
}

// request sends one request with a fresh id and returns its response
// (without the id).
func (c *sftpClient) request(typ byte, body []byte) (byte, []byte, error) {
	c.id++
	p := binary.BigEndian.AppendUint32(nil, c.id)
	if err := c.send(typ, append(p, body...)); err != nil {
		return 0, nil, err
	}
	rt, r, err := c.recv()
	if err != nil {
		return 0, nil, err
	}
	if len(r) < 4 {
		return 0, nil, errors.New("SFTP: short response")
	}
	return rt, r[4:], nil
}

// statusErr turns a STATUS response into an error (nil for OK).
func statusErr(op string, r []byte) error {
	if len(r) < 4 {
		return errors.New("SFTP: short status")
	}
	code := binary.BigEndian.Uint32(r)
	if code == fxOK {
		return nil
	}
	msg := ""
	if len(r) >= 8 {
		if l := binary.BigEndian.Uint32(r[4:]); int(l) <= len(r)-8 {
			msg = string(r[8 : 8+l])
		}
	}
	return fmt.Errorf("SFTP %s: %s (code %d)", op, msg, code)
}

func (c *sftpClient) simple(op string, typ byte, body []byte) error {
	rt, r, err := c.request(typ, body)
	if err != nil {
		return err
	}
	if rt != fxpStatus {
		return fmt.Errorf("SFTP %s: unexpected answer", op)
	}
	return statusErr(op, r)
}

func (c *sftpClient) handle(op string, typ byte, body []byte) ([]byte, error) {
	rt, r, err := c.request(typ, body)
	if err != nil {
		return nil, err
	}
	switch rt {
	case fxpHandle:
		if len(r) < 4 || int(binary.BigEndian.Uint32(r)) > len(r)-4 {
			return nil, errors.New("SFTP: bad handle")
		}
		return r[4 : 4+binary.BigEndian.Uint32(r)], nil
	case fxpStatus:
		return nil, statusErr(op, r)
	}
	return nil, fmt.Errorf("SFTP %s: unexpected answer", op)
}

// mkdirAll creates the folders of dir that are missing.
func (c *sftpClient) mkdirAll(dir string) {
	cur := ""
	if strings.HasPrefix(dir, "/") {
		cur = "/"
	}
	for _, part := range strings.Split(strings.Trim(dir, "/"), "/") {
		if part == "" {
			continue
		}
		cur = path.Join(cur, part)
		body := appendString(nil, cur)
		body = binary.BigEndian.AppendUint32(body, 0)
		_ = c.simple("mkdir", fxpMkdir, body) // fails when it exists
	}
}

// upload writes r to dir/name through a temporary name, renamed at the end.
func (c *sftpClient) upload(dir, name string, r io.Reader) error {
	if dir != "" {
		c.mkdirAll(dir)
	}
	final := path.Join(dir, name)
	part := final + ".part"
	body := appendString(nil, part)
	body = binary.BigEndian.AppendUint32(body, openWrite|openCreate|openTrunc)
	body = binary.BigEndian.AppendUint32(body, 0)
	h, err := c.handle("open", fxpOpen, body)
	if err != nil {
		return err
	}
	var off uint64
	buf := make([]byte, sftpChunk)
	pending := 0
	var werr error
	collect := func(n int) {
		for ; n > 0; n-- {
			rt, r, err := c.recv()
			pending--
			if err != nil {
				werr = err
				return
			}
			if rt != fxpStatus || len(r) < 4 {
				werr = errors.New("SFTP write: unexpected answer")
				continue
			}
			if e := statusErr("write", r[4:]); e != nil && werr == nil {
				werr = e
			}
		}
	}
	for werr == nil {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			c.id++
			p := binary.BigEndian.AppendUint32(nil, c.id)
			p = appendString(p, string(h))
			p = binary.BigEndian.AppendUint64(p, off)
			p = appendString(p, string(buf[:n]))
			if err := c.send(fxpWrite, p); err != nil {
				werr = err
				break
			}
			off += uint64(n)
			pending++
			if pending >= sftpWindow {
				collect(1)
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
				werr = rerr
			}
			break
		}
	}
	if werr == nil {
		collect(pending)
	}
	cerr := c.simple("close", fxpClose, appendString(nil, string(h)))
	if werr != nil {
		_ = c.simple("remove", fxpRemove, appendString(nil, part))
		return werr
	}
	if cerr != nil {
		return cerr
	}
	_ = c.simple("remove", fxpRemove, appendString(nil, final)) // SFTP v3 rename does not overwrite
	return c.simple("rename", fxpRename, appendString(appendString(nil, part), final))
}

// list returns the names in dir.
func (c *sftpClient) list(dir string) ([]string, error) {
	if dir == "" {
		dir = "."
	}
	h, err := c.handle("opendir", fxpOpendir, appendString(nil, dir))
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.simple("close", fxpClose, appendString(nil, string(h))) }()
	var names []string
	for {
		rt, r, err := c.request(fxpReaddir, appendString(nil, string(h)))
		if err != nil {
			return nil, err
		}
		if rt == fxpStatus {
			if len(r) >= 4 && binary.BigEndian.Uint32(r) == fxEOF {
				return names, nil
			}
			return nil, statusErr("readdir", r)
		}
		if rt != fxpName {
			return nil, errors.New("SFTP readdir: unexpected answer")
		}
		rd := bytes.NewReader(r)
		var count uint32
		if binary.Read(rd, binary.BigEndian, &count) != nil {
			return nil, errors.New("SFTP readdir: bad answer")
		}
		for i := uint32(0); i < count; i++ {
			name, err1 := readString(rd)
			_, err2 := readString(rd) // long name
			if err1 != nil || err2 != nil || skipAttrs(rd) != nil {
				return nil, errors.New("SFTP readdir: bad answer")
			}
			if name != "." && name != ".." {
				names = append(names, name)
			}
		}
	}
}

func (c *sftpClient) remove(p string) error {
	return c.simple("remove", fxpRemove, appendString(nil, p))
}

func readString(r *bytes.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	if int(n) > r.Len() {
		return "", io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return string(b), err
}

func skipAttrs(r *bytes.Reader) error {
	var flags uint32
	if err := binary.Read(r, binary.BigEndian, &flags); err != nil {
		return err
	}
	skip := 0
	if flags&0x1 != 0 {
		skip += 8
	}
	if flags&0x2 != 0 {
		skip += 8
	}
	if flags&0x4 != 0 {
		skip += 4
	}
	if flags&0x8 != 0 {
		skip += 8
	}
	if _, err := r.Seek(int64(skip), io.SeekCurrent); err != nil {
		return err
	}
	if flags&0x80000000 != 0 {
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return err
		}
		for i := uint32(0); i < 2*n; i++ {
			if _, err := readString(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// TestSFTP connects, writes and removes a small file in the folder. It
// returns the server's host key fingerprint (also when it is not trusted
// yet: then the error is an *ErrHostKey).
func TestSFTP(ctx context.Context, c SFTP) (string, error) {
	var fp string
	cl, err := dialSFTP(ctx, c, &fp)
	if err != nil {
		return fp, err
	}
	defer cl.Close()
	name := ".emailzit-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := cl.upload(c.Dir, name, strings.NewReader("EmailZit backup test\n")); err != nil {
		return fp, err
	}
	return fp, cl.remove(path.Join(c.Dir, name))
}

// UploadSFTP copies r to the folder as name and removes the oldest backups
// there (names that start with prefix) beyond keep.
func UploadSFTP(ctx context.Context, c SFTP, name, prefix string, keep int, r io.Reader) error {
	cl, err := dialSFTP(ctx, c, nil)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := cl.upload(c.Dir, name, r); err != nil {
		return err
	}
	names, err := cl.list(c.Dir)
	if err != nil {
		return nil // the copy is there; pruning can wait for the next one
	}
	var ours []string
	for _, n := range names {
		if strings.HasPrefix(n, prefix) && !strings.HasSuffix(n, ".part") {
			ours = append(ours, n)
		}
	}
	// The names hold the time (prefix-YYYYMMDD-HHMMSS), so they sort by age.
	slices.Sort(ours)
	for len(ours) > keep && keep > 0 {
		_ = cl.remove(path.Join(c.Dir, ours[0]))
		ours = ours[1:]
	}
	return nil
}
