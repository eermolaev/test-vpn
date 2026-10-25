package dnsintercept

import (
	"errors"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var errBadQuery = errors.New("dns: malformed query")

// question returns the ID and first question name (without trailing dot).
func question(q []byte) (uint16, string, dnsmessage.Type, error) {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return 0, "", 0, errBadQuery
	}
	qs, err := p.Question()
	if err != nil {
		return h.ID, "", 0, errBadQuery
	}
	return h.ID, strings.TrimSuffix(strings.ToLower(qs.Name.String()), "."), qs.Type, nil
}

// errorResponse builds a reply with the given rcode for query q.
func errorResponse(q []byte, rcode dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, _ := p.AllQuestions()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	if b.StartQuestions() == nil {
		for _, q := range qs {
			_ = b.Question(q)
		}
	}
	out, _ := b.Finish()
	return out
}

// truncated reports whether the TC bit is set.
func truncated(resp []byte) bool { return len(resp) > 2 && resp[2]&0x02 != 0 }

// answerIPs returns IPv4 addresses and the minimum TTL from a response.
func answerIPs(resp []byte) ([]netip.Addr, time.Duration) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0
	}
	var ips []netip.Addr
	ttl := maxTTL
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA && h.Class == dnsmessage.ClassINET {
			a, err := p.AResource()
			if err != nil {
				break
			}
			ips = append(ips, netip.AddrFrom4(a.A))
			ttl = min(ttl, time.Duration(h.TTL)*time.Second)
			continue
		}
		if err := p.SkipAnswer(); err != nil {
			break
		}
	}
	return ips, ttl
}

// withID returns a copy of msg with its ID replaced.
func withID(msg []byte, id uint16) []byte {
	out := append([]byte(nil), msg...)
	out[0], out[1] = byte(id>>8), byte(id)
	return out
}
