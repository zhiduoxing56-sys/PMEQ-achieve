package discovery

import (
	"bytes"
	"encoding/binary"
	"io"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorquery"
	dpfcodec "pmeq/internal/dpf128/codec"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
)

func put(b *bytes.Buffer, x any) { check(binary.Write(b, binary.LittleEndian, x)) }
func get(b *bytes.Reader, x any) { check(binary.Read(b, binary.LittleEndian, x)) }
func encodeToken(t cloudToken) []byte {
	var b bytes.Buffer
	b.WriteString("PMEQQU11")
	put(&b, t.packet)
	put(&b, uint32(len(t.anchor)))
	put(&b, t.keep)
	for i, a := range t.anchor {
		put(&b, a.PID)
		put(&b, a.BucketID)
		b.Write(dpfcodec.EncodeKey(a.DPFKey))
		put(&b, a.Ltilde)
		put(&b, a.RplusTilde)
		put(&b, t.f[i])
	}
	raw, e := targetrouting.EncodeToken(t.target)
	check(e)
	put(&b, uint32(len(raw)))
	b.Write(raw)
	for _, p := range t.target.Position {
		put(&b, p)
	}
	put(&b, t.agg.PacketID)
	put(&b, t.agg.QueryID)
	put(&b, uint32(t.agg.R))
	put(&b, t.agg.FBound)
	put(&b, t.agg.KeepBound)
	return b.Bytes()
}
func decodeToken(raw []byte, m targetrouting.Manifest, party uint8) (t cloudToken, err error) {
	defer caught(&err)
	b := bytes.NewReader(raw)
	magic := make([]byte, 8)
	_, err = io.ReadFull(b, magic)
	check(err)
	if string(magic) != "PMEQQU11" {
		check(ErrBinding)
	}
	get(b, &t.packet)
	var n uint32
	get(b, &n)
	if n < 1 || n > 14 {
		check(ErrBinding)
	}
	get(b, &t.keep)
	t.anchor = make([]anchorfilter.PartyQuery, n)
	t.f = make([]uint32, n)
	for i := range t.anchor {
		a := &t.anchor[i]
		get(b, &a.PID)
		get(b, &a.BucketID)
		k := make([]byte, dpfcodec.KeyBytes)
		_, err = io.ReadFull(b, k)
		check(err)
		a.DPFKey, err = dpfcodec.DecodeKey(k)
		check(err)
		get(b, &a.Ltilde)
		get(b, &a.RplusTilde)
		get(b, &t.f[i])
	}
	get(b, &n)
	if n > 42+42*16 {
		check(ErrBinding)
	}
	tb := make([]byte, n)
	_, err = io.ReadFull(b, tb)
	check(err)
	t.target, err = targetrouting.DecodeToken(m, party, tb)
	check(err)
	t.target.Position = make([]anchorfilter.PositionToken, len(t.target.Words))
	for i := range t.target.Position {
		get(b, &t.target.Position[i])
	}
	get(b, &t.agg.PacketID)
	get(b, &t.agg.QueryID)
	get(b, &n)
	t.agg.R = int(n)
	get(b, &t.agg.FBound)
	get(b, &t.agg.KeepBound)
	if b.Len() != 0 || t.agg.QueryID != t.target.QueryID {
		check(ErrBinding)
	}
	return
}
func generate(q Query, k UserKeys, u *UserPacket, m targetrouting.Manifest) (out [2][]byte, err error) {
	defer caught(&err)
	check(Validate(q))
	check(u.g.claim())
	cs := anchorfilter.QueryChunks(q.Anchor)
	if len(cs) != len(u.anchor) {
		check(ErrBinding)
	}
	a, b, e := targetquery.GeneratePositionTokens(m, k.Target, q.Target, uint32(q.TauTarget), u.target)
	check(e)
	agg, e := u.agg.Token(a.QueryID, q.TauTarget)
	check(e)
	l, e := aggregation.Threshold(len(cs), q.TauAnchor)
	check(e)
	keep, e := u.keep.Mask(l)
	check(e)
	ts := [2]cloudToken{{packet: u.id, keep: keep, target: a, agg: agg}, {packet: u.id, keep: keep, target: b, agg: agg}}
	for i, c := range cs {
		x, y, e := anchorquery.MakeOccurrence(k.Anchor, c, uint32(q.TauAnchor), 62, 16, &u.anchor[i])
		check(e)
		if x.BucketID != u.buckets[i] {
			check(ErrBinding)
		}
		f, e := u.f[i].Mask(1)
		check(e)
		ts[0].anchor = append(ts[0].anchor, x)
		ts[1].anchor = append(ts[1].anchor, y)
		ts[0].f = append(ts[0].f, f)
		ts[1].f = append(ts[1].f, f)
	}
	out[0] = encodeToken(ts[0])
	out[1] = encodeToken(ts[1])
	return
}
