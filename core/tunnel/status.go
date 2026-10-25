package tunnel

import (
	"encoding/json"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
)

// State of the tunnel.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting" // engine lost, kill switch active
	StateFailed       State = "failed"       // all attempts exhausted, kill switch active
	StateStopped      State = "stopped"
)

// Stats is a snapshot of router counters.
type Stats struct {
	TCPTunnel  int64 `json:"tcpTunnel"`
	TCPDirect  int64 `json:"tcpDirect"`
	TCPReject  int64 `json:"tcpReject"`
	UDPTunnel  int64 `json:"udpTunnel"`
	UDPDirect  int64 `json:"udpDirect"`
	UDPReject  int64 `json:"udpReject"`
	DNSQueries int64 `json:"dnsQueries"`
	DNSDirect  int64 `json:"dnsDirect"`
	DNSTunnel  int64 `json:"dnsTunnel"`
	DNSFailed  int64 `json:"dnsFailed"`

	BytesTunnelUp   int64 `json:"bytesTunnelUp"`
	BytesTunnelDown int64 `json:"bytesTunnelDown"`
	BytesDirectUp   int64 `json:"bytesDirectUp"`
	BytesDirectDown int64 `json:"bytesDirectDown"`
	ActiveFlows     int   `json:"activeFlows"`
}

// Status is reported to the app. TransportID contains the server endpoint and
// must be redacted before logging.
type Status struct {
	State         State  `json:"state"`
	TransportID   string `json:"transportId,omitempty"`
	TransportKind string `json:"transportKind,omitempty"`
	Attempt       int    `json:"attempt,omitempty"`
	Round         int    `json:"round,omitempty"`
	// Failures counts failed connection attempts since the tunnel was last
	// up; the daemon uses it to switch to another profile.
	Failures     int            `json:"failures,omitempty"`
	ErrorClass   errclass.Class `json:"errorClass,omitempty"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
	Since        time.Time      `json:"since"`
	Exclusions   int            `json:"exclusions"`
	DNSServers   []string       `json:"dnsServers"`
	Stats        Stats          `json:"stats"`
}

// JSON encodes the status.
func (s Status) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}
