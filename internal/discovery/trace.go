package discovery

import (
	"encoding/hex"
	"fmt"
)

// Metadata only: no payload copies, payload hashes, inputs, outputs or masks.
type FrameAudit struct {
	Seq          uint32
	Phase        int
	Kind         string
	BodyBytes    int
	PublicHeader string
}

func (s *endpoint) sendKind(kind string, body []byte) []byte { s.nextKind = kind; return s.send(body) }
func (s *endpoint) audit(body []byte) {
	kind := s.nextKind
	s.nextKind = ""
	if kind == "" {
		kind = fmt.Sprintf("existing-phase-%d", s.phase)
	}
	s.trace = append(s.trace, FrameAudit{s.seq, s.phase, kind, len(body), hex.EncodeToString(append(append([]byte(nil), s.query[:]...), s.packet[:]...))})
}
