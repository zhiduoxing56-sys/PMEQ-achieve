package discovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/candidatequery"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"testing"
	"time"
)

func ticketCodec(t *testing.T, save func(*material.StreamEncoder), load func(*material.StreamDecoder) error) {
	t.Helper()
	var raw bytes.Buffer
	e := &material.StreamEncoder{W: &raw}
	save(e)
	if e.Err != nil {
		t.Fatal(e.Err)
	}
	d := &material.StreamDecoder{R: bytes.NewReader(raw.Bytes())}
	if err := load(d); err != nil {
		t.Fatal(err)
	}
	if d.Err != nil {
		t.Fatal(d.Err)
	}
	if d.R.(*bytes.Reader).Len() != 0 {
		t.Fatal("unread packet material")
	}
}

func cloneFixtureUser(t *testing.T, u *UserPacket, shape targetaggregation.Shape) *UserPacket {
	t.Helper()
	v := &UserPacket{g: &guard{ledger: u.g.ledger, id: u.id}, id: u.id, layout: u.layout, compaction: u.compaction, buckets: append([]uint32(nil), u.buckets...), movieBinding: u.movieBinding, keyFingerprint: u.keyFingerprint}
	v.anchor = make([]anchorfilter.UserPreprocessing, len(u.anchor))
	for i := range u.anchor {
		i := i
		ticketCodec(t, func(e *material.StreamEncoder) { u.anchor[i].WriteOwn(e) }, func(d *material.StreamDecoder) (err error) { v.anchor[i], err = anchorfilter.ReadUserOwn(d, 7); return })
	}
	ticketCodec(t, func(e *material.StreamEncoder) { u.keep.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) { v.keep, err = aggregation.ReadBoundOwn(d); return })
	v.target = make([]anchorfilter.UserPreprocessing, len(u.target))
	for i := range u.target {
		i := i
		ticketCodec(t, func(e *material.StreamEncoder) { u.target[i].WriteOwn(e) }, func(d *material.StreamDecoder) (err error) { v.target[i], err = anchorfilter.ReadUserOwn(d, 7); return })
	}
	ticketCodec(t, func(e *material.StreamEncoder) { u.agg.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
		v.agg, err = targetaggregation.ReadUserOwn(d, shape)
		return
	})
	return v
}

func cloneFixtureParty(t *testing.T, p *PartyPacket, s *Static, shape targetaggregation.Shape, capacities []int) *PartyPacket {
	t.Helper()
	v := &PartyPacket{g: &guard{ledger: p.g.ledger, id: p.id}, id: p.id, party: p.party, capacity: p.capacity, movieBinding: p.movieBinding}
	v.anchor = make([]anchorPacket, len(p.anchor))
	for i := range p.anchor {
		i := i
		old := p.anchor[i]
		own, err := s.anchorFor(old.bucket)
		if err != nil {
			t.Fatal(err)
		}
		cur := &v.anchor[i]
		cur.bucket = old.bucket
		cur.empty = old.empty
		ticketCodec(t, func(e *material.StreamEncoder) { old.position.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
			cur.position, err = anchorfilter.ReadPartyOwn(d, own.T, 7)
			return
		})
		cur.zeroRef = old.zeroRef
		v.persistentRefs = append(v.persistentRefs, *old.zeroRef)
		ticketCodec(t, func(e *material.StreamEncoder) { old.z.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
			cur.z, err = incidence.ReadTriplesOwn(d, p.party, own.D, 1)
			return
		})
		if p.party == 0 {
			ticketCodec(t, func(e *material.StreamEncoder) { old.p0.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
				cur.p0, err = aggregation.ReadPermPrep0Own(d, own.Stage0, len(s.payload.Slots))
				return
			})
		} else {
			ticketCodec(t, func(e *material.StreamEncoder) { old.p1.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
				cur.p1, err = aggregation.ReadPermPrep1Own(d, own.Stage1, len(s.payload.Slots))
				return
			})
		}
	}
	ticketCodec(t, func(e *material.StreamEncoder) { p.keep.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
		v.keep, err = aggregation.ReadComparisonOwn(d, p.party, len(s.payload.Slots))
		return
	})
	if p.party == 0 {
		ticketCodec(t, func(e *material.StreamEncoder) { p.c0.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
			v.c0, err = aggregation.ReadCompaction0Own(d, s.payload.LayoutID, len(s.payload.Slots), s.target.Manifest().TargetBucketBits)
			return
		})
	} else {
		ticketCodec(t, func(e *material.StreamEncoder) { p.c1.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
			v.c1, err = aggregation.ReadCompaction1Own(d, s.payload.LayoutID, len(s.payload.Slots), s.target.Manifest().TargetBucketBits)
			return
		})
	}
	ticketCodec(t, func(e *material.StreamEncoder) { p.pe.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
		v.pe, err = targetpe.ReadPacketOwn(d, p.party, s.target.Lineage(), shape.G)
		return
	})
	ticketCodec(t, func(e *material.StreamEncoder) { p.position.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
		v.position, err = targetposition.ReadPacketOwn(d, p.party, s.target.Lineage(), capacities, 7, 62)
		return
	})
	ticketCodec(t, func(e *material.StreamEncoder) { p.agg.WriteOwn(e) }, func(d *material.StreamDecoder) (err error) {
		v.agg, err = targetaggregation.ReadPacketOwn(d, p.party, s.target.Lineage(), shape)
		return
	})
	return v
}

func runRestoredNestedMaterials(t *testing.T, backend anchorfilter.SCMPBackend) {
	f := newDomainFixture(t, 7, true)
	f.shape.D = 26
	u, p0, p1, _, err := Provision(f.st[0], f.st[1], f.buckets, f.cap, f.shape, backend)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ticketDir := filepath.Join(root, hex.EncodeToString(u.id[:]))
	_, err = PersistReservation(root, ticketDir, u, p0, p1, f.st[0], f.st[1])
	if err != nil {
		t.Fatal(err)
	}
	u2 := cloneFixtureUser(t, u, f.shape)
	a2 := cloneFixtureParty(t, p0, f.st[0], f.shape, f.cap)
	b2 := cloneFixtureParty(t, p1, f.st[1], f.shape, f.cap)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, _, err := RunLocal(ctx, f.q, f.keys, u2, f.st, [2]*PartyPacket{a2, b2}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pairs) != 1 || result.Pairs[0] != (candidatequery.Pair{AnchorRecordID: 1001, TargetRecordID: 901}) {
		t.Fatalf("restored protocol result: %+v", result)
	}
	if _, _, err = RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{p0, p1}, backend); err == nil {
		t.Fatal("original material reused after restored execution")
	}
}

func TestRestoredNestedMaterialsRunTwoCloudProtocol(t *testing.T) {
	runRestoredNestedMaterials(t, domainBackend{})
}
