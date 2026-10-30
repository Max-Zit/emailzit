package submit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Send hands one message to the EmailZit server (emailzit-sendmail).
func Send(socket string, req Request, msg io.Reader) (*Reply, error) {
	c, err := net.DialTimeout("unix", socket, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(c, 64<<10)
	_, werr := w.Write(append(b, '\n'))
	if werr == nil {
		_, werr = io.Copy(w, msg)
	}
	if werr == nil {
		werr = w.Flush()
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	// the server may answer early (message too large) and stop reading
	line, err := bufio.NewReader(io.LimitReader(c, 64<<10)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		if werr != nil {
			return nil, werr
		}
		return nil, errors.New("no answer from the EmailZit server")
	}
	var r Reply
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, errors.New("bad answer from the EmailZit server")
	}
	return &r, nil
}
