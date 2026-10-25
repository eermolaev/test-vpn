// Package ipc is the protocol between the root daemon and the TUI/CLI: JSON
// lines over a unix socket. Only root and the user who installed the daemon
// may connect (peer credentials are checked).
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// DefaultSocket is the daemon socket path on macOS.
const DefaultSocket = "/var/run/testvpn.sock"

// Request is one call.
type Request struct {
	ID   uint64          `json:"id"`
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response answers a Request.
type Response struct {
	ID    uint64          `json:"id"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Handler serves a command; the returned value is JSON-encoded.
type Handler func(cmd string, args json.RawMessage) (any, error)

// Server accepts connections on a unix socket.
type Server struct {
	ln         net.Listener
	handler    Handler
	allowedUID int // -1 allows any user (tests)
	wg         sync.WaitGroup
}

// Listen creates the socket at path, owned by allowedUID with mode 0600 (root
// can always connect). allowedUID < 0 skips ownership and peer checks.
func Listen(path string, allowedUID int, h Handler) (*Server, error) {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if allowedUID >= 0 {
		if err := os.Chown(path, allowedUID, -1); err != nil {
			ln.Close()
			return nil, err
		}
		os.Chmod(path, 0o600)
	}
	s := &Server{ln: ln, handler: h, allowedUID: allowedUID}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		if s.allowedUID >= 0 {
			uid, err := peerUID(c)
			if err != nil || (uid != 0 && uid != s.allowedUID) {
				c.Close()
				continue
			}
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	enc := json.NewEncoder(c)
	for sc.Scan() {
		var req Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			enc.Encode(Response{Error: "bad request"})
			continue
		}
		resp := Response{ID: req.ID}
		v, err := s.handler(req.Cmd, req.Args)
		if err != nil {
			resp.Error = err.Error()
		} else if v != nil {
			resp.Data, _ = json.Marshal(v)
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

// Close stops accepting connections.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

// Client is a connection to the daemon. It is safe for concurrent use.
type Client struct {
	mu   sync.Mutex
	c    net.Conn
	sc   *bufio.Scanner
	enc  *json.Encoder
	next uint64
}

// ErrNotRunning means the daemon socket is not available.
var ErrNotRunning = errors.New("the VPN service is not running (install it with: sudo testvpn install)")

// Dial connects to the daemon.
func Dial(path string) (*Client, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	return &Client{c: c, sc: sc, enc: json.NewEncoder(c)}, nil
}

// Call sends a command and decodes the result into out (may be nil).
func (cl *Client) Call(cmd string, args, out any) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.next++
	req := Request{ID: cl.next, Cmd: cmd}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		req.Args = b
	}
	cl.c.SetDeadline(time.Now().Add(60 * time.Second))
	if err := cl.enc.Encode(req); err != nil {
		return err
	}
	if !cl.sc.Scan() {
		if err := cl.sc.Err(); err != nil {
			return err
		}
		return errors.New("daemon closed the connection")
	}
	var resp Response
	if err := json.Unmarshal(cl.sc.Bytes(), &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

// Close closes the connection.
func (cl *Client) Close() error { return cl.c.Close() }
