package testenv

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/eermolaev/test-vpn/core/profile"
	"golang.org/x/crypto/ssh"
)

// SSHServer is an in-process SSH server that forwards direct-tcpip
// channels, with password and public key login.
type SSHServer struct {
	Addr        string
	Port        int
	User        string
	Password    string
	ClientKey   string // OpenSSH private key accepted by the server
	Fingerprint string // SHA256 fingerprint of the host key

	mu       sync.Mutex
	forwards int
	ln       net.Listener
}

// Forwards returns the number of forwarded connections.
func (s *SSHServer) Forwards() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forwards
}

// Config returns a password profile for the server.
func (s *SSHServer) Config() *profile.SSHConfig {
	return &profile.SSHConfig{Address: s.Addr, Port: s.Port, Username: s.User, Password: s.Password}
}

// Close stops accepting connections.
func (s *SSHServer) Close() { s.ln.Close() }

// StartSSH starts the server on 127.0.0.1.
func StartSSH(t testing.TB) *SSHServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(clientPub)
	s := &SSHServer{
		User: "tester", Password: "secret-pass",
		ClientKey:   string(pem.EncodeToMemory(block)),
		Fingerprint: ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if m.User() == s.User && string(p) == s.Password {
				return nil, nil
			}
			return nil, io.EOF
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if m.User() == s.User && string(k.Marshal()) == string(sshPub.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { ln.Close() })
	s.Addr = "127.0.0.1"
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *SSHServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		// RFC 4254 7.2: host, port, originator host, originator port.
		var req struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &req); err != nil {
			nc.Reject(ssh.ConnectionFailed, "bad request")
			continue
		}
		dst, err := net.Dial("tcp", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		s.mu.Lock()
		s.forwards++
		s.mu.Unlock()
		go ssh.DiscardRequests(creqs)
		go func() {
			defer ch.Close()
			defer dst.Close()
			go func() { io.Copy(dst, ch); dst.(*net.TCPConn).CloseWrite() }()
			io.Copy(ch, dst)
		}()
	}
}
