package discovery

import (
	"bytes"
	"encoding/binary"
	"io"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorquery"
	dpfcodec "pmeq/internal/dpf128/codec"
	"pmeq/internal/imdbprod"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
)

func put(b *bytes.Buffer, x any) { check(binary.Write(b, binary.LittleEndian, x)) }
func get(b *bytes.Reader, x any) { check(binary.Read(b, binary.LittleEndian, x)) }
func encodeToken(t cloudToken) []byte {
	var b bytes.Buffer
	if t.movieBinding == [32]byte{} {
		b.WriteString("PMEQQU12")
	} else {
		b.WriteString("PMEQQU13")
		b.Write(t.movieBinding[:])
	}
	put(&b, t.packet)
	put(&b, uint32(len(t.anchor)))
	put(&b, t.keep)
	for _, a := range t.anchor {
		put(&b, a.PID)
		if t.target.Manifest.TargetBucketBits > 16 {
			put(&b, a.BucketID)
		} else {
			put(&b, uint16(a.BucketID))
		}
		b.Write(dpfcodec.EncodeKey(a.DPFKey))
		put(&b, a.Ltilde)
		put(&b, a.RplusTilde)
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
	return decodeTokenWithProfile(raw, m, party, [32]byte{})
}
func decodeTokenWithProfile(raw []byte, m targetrouting.Manifest, party uint8, binding [32]byte) (t cloudToken, err error) {
	defer caught(&err)
	b := bytes.NewReader(raw)
	magic := make([]byte, 8)
	_, err = io.ReadFull(b, magic)
	check(err)
	if binding == [32]byte{} {
		if string(magic) != "PMEQQU12" {
			check(ErrBinding)
		}
	} else {
		if string(magic) != "PMEQQU13" {
			check(ErrBinding)
		}
		var actual [32]byte
		_, err = io.ReadFull(b, actual[:])
		check(err)
		if actual != binding {
			check(ErrBinding)
		}
		t.movieBinding = actual
	}
	get(b, &t.packet)
	var n uint32
	get(b, &n)
	if n < 1 || n > 14 {
		check(ErrBinding)
	}
	get(b, &t.keep)
	t.anchor = make([]anchorfilter.PartyQuery, n)
	for i := range t.anchor {
		a := &t.anchor[i]
		get(b, &a.PID)
		if m.TargetBucketBits > 16 {
			get(b, &a.BucketID)
		} else {
			var narrow uint16
			get(b, &narrow)
			a.BucketID = uint32(narrow)
		}
		k := make([]byte, dpfcodec.KeyBytes)
		_, err = io.ReadFull(b, k)
		check(err)
		a.DPFKey, err = dpfcodec.DecodeKey(k)
		check(err)
		get(b, &a.Ltilde)
		get(b, &a.RplusTilde)
	}
	get(b, &n)
	if n > uint32(targetrouting.TokenBytesForBits(m.TargetBucketBits, 16)) {
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
	movie := u.movieBinding != [32]byte{}
	if movie {
		check(imdbprod.Production().CheckQuery(q.Anchor, q.Target, q.TauAnchor, q.TauTarget))
	} else {
		check(Validate(q))
	}
	check(u.g.claim())
	cs := anchorfilter.QueryChunks(q.Anchor)
	if movie {
		cs, err = anchorfilter.QueryChunksWithQ(q.Anchor, imdbprod.Q, imdbprod.AnchorSignatures)
		check(err)
	}
	if len(cs) != len(u.anchor) {
		check(ErrBinding)
	}
	var a, b targetrouting.QueryToken
	var e error
	if movie {
		a, b, e = targetquery.GenerateMoviePositionTokens(m, k.Target, q.Target, uint32(q.TauTarget), u.target)
	} else {
		a, b, e = targetquery.GeneratePositionTokens(m, k.Target, q.Target, uint32(q.TauTarget), u.target)
	}
	check(e)
	agg, e := u.agg.Token(a.QueryID, q.TauTarget)
	check(e)
	l, e := aggregation.Threshold(len(cs), q.TauAnchor)
	check(e)
	keep, e := u.keep.Mask(l)
	check(e)
	ts := [2]cloudToken{{packet: u.id, keep: keep, target: a, agg: agg, movieBinding: u.movieBinding}, {packet: u.id, keep: keep, target: b, agg: agg, movieBinding: u.movieBinding}}
	for i, c := range cs {
		var x, y anchorfilter.PartyQuery
		var e error
		if movie {
			x, y, e = anchorquery.MakeMovieOccurrence(k.Anchor, c, uint32(q.TauAnchor), imdbprod.PositionMax, int(m.TargetBucketBits), &u.anchor[i])
		} else {
			x, y, e = anchorquery.MakeOccurrence(k.Anchor, c, uint32(q.TauAnchor), 62, int(m.TargetBucketBits), &u.anchor[i])
		}
		check(e)
		if x.BucketID != u.buckets[i] {
			check(ErrBinding)
		}
		ts[0].anchor = append(ts[0].anchor, x)
		ts[1].anchor = append(ts[1].anchor, y)
	}
	out[0] = encodeToken(ts[0])
	out[1] = encodeToken(ts[1])
	return
}
