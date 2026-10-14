package candidatequery

// Version 2 is the cloud execution endpoint: exactly M pairs, with no Keep
// shares, candidate ordinal, local coordinate or grouping label in the payload.
import (
	"encoding/binary"
	"pmeq/internal/aggregation"
	"pmeq/internal/domain"
	"pmeq/internal/share"
)

const SelectedHeaderBytes = 130

func EncodeSelected(party uint8, w Binding, s aggregation.PairSelection) ([]byte, error) {
	if party > 1 || w.Manifest.Validate() != nil || w.LayoutID == [16]byte{} || w.CompactionID == [16]byte{} || w.QueryID == [16]byte{} || s.ShuffleID == [16]byte{} || len(s.Anchor) != len(s.Target) || uint64(len(s.Anchor)) > uint64(^uint32(0)) || len(s.Anchor) > (int(^uint(0)>>1)-SelectedHeaderBytes)/16 {
		return nil, ErrResult
	}
	b := make([]byte, SelectedHeaderBytes+16*len(s.Anchor))
	copy(b, "PMEQPM02")
	b[8] = party
	copy(b[9:], w.Manifest.IndexID[:])
	b[25] = w.Manifest.TargetBucketBits
	binary.LittleEndian.PutUint32(b[26:], w.Manifest.Q)
	copy(b[30:], w.LayoutID[:])
	copy(b[46:], w.CompactionID[:])
	copy(b[62:], w.QueryID[:])
	copy(b[78:], s.ShuffleID[:])
	binary.LittleEndian.PutUint32(b[94:], uint32(len(s.Anchor)))
	copy(b[98:], s.OrderDigest[:])
	for i := range s.Anchor {
		at := SelectedHeaderBytes + 16*i
		binary.LittleEndian.PutUint64(b[at:], uint64(s.Anchor[i].Value()))
		binary.LittleEndian.PutUint64(b[at+8:], uint64(s.Target[i].Value()))
	}
	return b, nil
}

// DecodeSelected checks trusted public capacity C, not a hardcoded table size.
// It is also used by independent acceptance tests, which alone merge shares.
func DecodeSelected(party uint8, w Binding, b []byte, capacity int) (aggregation.PairSelection, error) {
	var out aggregation.PairSelection
	if party > 1 || capacity < 0 || capacity > (int(^uint(0)>>1)-SelectedHeaderBytes)/16/16 || len(b) < SelectedHeaderBytes || string(b[:8]) != "PMEQPM02" || b[8] != party || string(b[9:25]) != string(w.Manifest.IndexID[:]) || b[25] != w.Manifest.TargetBucketBits || binary.LittleEndian.Uint32(b[26:]) != w.Manifest.Q || string(b[30:46]) != string(w.LayoutID[:]) || string(b[46:62]) != string(w.CompactionID[:]) || string(b[62:78]) != string(w.QueryID[:]) {
		return out, ErrResult
	}
	m := int(binary.LittleEndian.Uint32(b[94:]))
	if m > 16*capacity || len(b) != SelectedHeaderBytes+16*m {
		return out, ErrResult
	}
	copy(out.ShuffleID[:], b[78:94])
	copy(out.OrderDigest[:], b[98:130])
	if out.ShuffleID == [16]byte{} {
		return out, ErrResult
	}
	out.Anchor = make([]share.Ring64Share, m)
	out.Target = make([]share.Ring64Share, m)
	for i := range out.Anchor {
		at := SelectedHeaderBytes + 16*i
		out.Anchor[i] = share.NewRing64Share(domain.Ring64(binary.LittleEndian.Uint64(b[at:])))
		out.Target[i] = share.NewRing64Share(domain.Ring64(binary.LittleEndian.Uint64(b[at+8:])))
	}
	return out, nil
}
