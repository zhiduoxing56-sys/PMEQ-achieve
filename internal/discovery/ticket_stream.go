package discovery

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
)

func productionShape() targetaggregation.Shape {
	return productionShapeForD(imdbprod.TargetDimension)
}

func productionShapeForD(d int) targetaggregation.Shape {
	return targetaggregation.Shape{K: imdbprod.CandidateCapacity, R: imdbprod.TargetSignatures,
		S: imdbprod.CandidateCapacity * imdbprod.TargetSignatures * imdbprod.TargetBucketSlots,
		G: imdbprod.CandidateCapacity * imdbprod.TargetBucketSlots, D: d}
}

func (u *UserPacket) writeOwn(e *material.StreamEncoder) {
	if u == nil || u.g == nil || u.movieBinding == [32]byte{} || len(u.anchor) != imdbprod.AnchorSignatures || len(u.target) != imdbprod.TargetSignatures || len(u.buckets) != len(u.anchor) || u.keep == nil || u.agg == nil {
		e.Err = ErrBinding
		return
	}
	if u.inventoryV3 {
		e.U8(3)
	} else {
		e.U8(1)
	}
	e.Bytes(u.id[:])
	if u.inventoryV3 {
		e.Bytes(u.bankID[:])
	}
	e.Bytes(u.layout[:])
	e.Bytes(u.movieBinding[:])
	e.Bytes(u.compaction[:])
	e.Blob([]byte(u.keyFingerprint))
	e.U32(uint32(len(u.anchor)))
	for i := range u.anchor {
		e.U32(u.buckets[i])
		u.anchor[i].WriteOwn(e)
	}
	u.keep.WriteOwn(e)
	e.U32(uint32(len(u.target)))
	for _, prep := range u.target {
		prep.WriteOwn(e)
	}
	u.agg.WriteOwn(e)
}

func readUserOwn(d *material.StreamDecoder, ticket [16]byte, binding [32]byte, layout [16]byte, fingerprint string, roleDir string, buckets []uint32, inventoryV3 bool, bankID [16]byte, dTarget int) (*UserPacket, error) {
	version := d.U8()
	if (inventoryV3 && version != 3) || (!inventoryV3 && version != 1) {
		return nil, ErrBinding
	}
	u := &UserPacket{g: &guard{ledger: roleDir, id: ticket}, buckets: append([]uint32(nil), buckets...), movieBinding: binding, keyFingerprint: fingerprint, inventoryV3: inventoryV3, bankID: bankID}
	d.Bytes(u.id[:])
	if inventoryV3 {
		var own [16]byte
		d.Bytes(own[:])
		if own != bankID || bankID == [16]byte{} {
			return nil, ErrBinding
		}
	}
	d.Bytes(u.layout[:])
	var ownBinding [32]byte
	d.Bytes(ownBinding[:])
	d.Bytes(u.compaction[:])
	keyID := string(d.Blob(64))
	if d.U32() != uint32(len(buckets)) || d.Err != nil || u.id != ticket || u.layout != layout || ownBinding != binding || keyID != fingerprint || u.compaction == [16]byte{} {
		return nil, ErrBinding
	}
	u.anchor = make([]anchorfilter.UserPreprocessing, len(buckets))
	for i := range buckets {
		if d.U32() != buckets[i] {
			return nil, ErrBinding
		}
		var err error
		u.anchor[i], err = anchorfilter.ReadUserOwn(d, imdbprod.PositionBin)
		if err != nil {
			return nil, err
		}
	}
	var err error
	u.keep, err = aggregation.ReadBoundOwn(d)
	if err != nil {
		return nil, err
	}
	if d.U32() != imdbprod.TargetSignatures {
		return nil, ErrBinding
	}
	u.target = make([]anchorfilter.UserPreprocessing, imdbprod.TargetSignatures)
	for i := range u.target {
		u.target[i], err = anchorfilter.ReadUserOwn(d, imdbprod.PositionBin)
		if err != nil {
			return nil, err
		}
	}
	u.agg, err = targetaggregation.ReadUserOwn(d, productionShapeForD(dTarget))
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (p *PartyPacket) writeOwn(e *material.StreamEncoder, s *Static) {
	if p == nil || p.g == nil || s == nil || p.party != s.party || p.party > 1 || p.movieBinding != s.movieBinding || p.capacity != imdbprod.CandidateCapacity || len(p.anchor) != imdbprod.AnchorSignatures || p.keep == nil || p.output != nil {
		e.Err = ErrBinding
		return
	}
	if p.inventoryV3 {
		e.U8(3)
	} else {
		e.U8(1)
	}
	e.U8(p.party)
	e.Bytes(p.id[:])
	if p.inventoryV3 {
		e.Bytes(p.bankID[:])
	}
	e.Bytes(p.movieBinding[:])
	e.U32(uint32(p.capacity))
	e.U32(uint32(len(p.anchor)))
	for i := range p.anchor {
		a := &p.anchor[i]
		e.U32(a.bucket)
		if a.empty {
			e.U8(1)
		} else {
			e.U8(0)
		}
		a.position.WriteOwn(e)
		if a.empty {
			continue
		}
		if a.zeroRef == nil || a.zero != nil || a.z == nil || (p.party == 0 && a.p0 == nil) || (p.party == 1 && a.p1 == nil) {
			e.Err = ErrBinding
			return
		}
		raw, err := json.Marshal(a.zeroRef.Binding)
		if err != nil {
			e.Err = err
			return
		}
		e.Blob(raw)
		e.Bytes(a.zeroRef.OwnStaticSHA[:])
		e.Bytes(a.zeroRef.OwnPacketSHA[:])
		a.z.WriteOwn(e)
		if p.party == 0 {
			a.p0.WriteOwn(e)
		} else {
			a.p1.WriteOwn(e)
		}
	}
	p.keep.WriteOwn(e)
	if p.party == 0 {
		p.c0.WriteOwn(e)
	} else {
		p.c1.WriteOwn(e)
	}
	p.pe.WriteOwn(e)
	if p.inventoryV3 {
		p.position.WriteInventoryOwn(e)
	} else {
		p.position.WriteOwn(e)
	}
	p.agg.WriteOwn(e)
}

func readPartyOwn(d *material.StreamDecoder, ticket [16]byte, binding [32]byte, roleDir string, buckets []uint32, s *Static, inventoryV3 bool, bankID [16]byte, dTarget int) (*PartyPacket, error) {
	version := d.U8()
	if s == nil || s.party > 1 || (inventoryV3 && version != 3) || (!inventoryV3 && version != 1) || d.U8() != s.party {
		return nil, ErrBinding
	}
	p := &PartyPacket{g: &guard{ledger: roleDir, id: ticket}, party: s.party, id: ticket, movieBinding: binding, capacity: imdbprod.CandidateCapacity, inventoryV3: inventoryV3, bankID: bankID}
	var ownID [16]byte
	var ownBinding [32]byte
	d.Bytes(ownID[:])
	if inventoryV3 {
		var ownBank [16]byte
		d.Bytes(ownBank[:])
		if ownBank != bankID || bankID == [16]byte{} {
			return nil, ErrBinding
		}
	}
	d.Bytes(ownBinding[:])
	if d.U32() != uint32(p.capacity) || d.U32() != uint32(len(buckets)) || d.Err != nil || ownID != ticket || ownBinding != binding || s.movieBinding != binding {
		return nil, ErrBinding
	}
	p.anchor = make([]anchorPacket, len(buckets))
	for i, bucket := range buckets {
		a := &p.anchor[i]
		if d.U32() != bucket {
			return nil, ErrBinding
		}
		a.bucket = bucket
		flag := d.U8()
		if flag > 1 {
			return nil, ErrBinding
		}
		a.empty = flag == 1
		var own AnchorStatic
		n := 0
		if !a.empty {
			var err error
			own, err = s.anchorFor(bucket)
			if err != nil {
				return nil, err
			}
			n = own.T
		} else if s.anchorStore != nil {
			if _, exists := s.anchorStore.Meta(bucket); exists {
				return nil, ErrBinding
			}
		}
		var err error
		a.position, err = anchorfilter.ReadPartyOwn(d, n, imdbprod.PositionBin)
		if err != nil {
			return nil, err
		}
		if a.empty {
			continue
		}
		raw := d.Blob(4096)
		var ref ZeroBinding
		if d.Err != nil || json.Unmarshal(raw, &ref) != nil || ref.Spec.Bucket != fmt.Sprint(bucket) || ref.Spec.T != own.T || ref.Spec.D != own.D || ref.Spec.StaticID != own.LabelID || ref.WholeTicket != fmt.Sprintf("%x", ticket) || ref.Occurrence != i {
			return nil, ErrBinding
		}
		zr := &zeroReference{Binding: ref, Root: filepath.Join(roleDir, "zero", ref.Spec.LayoutID, ref.Spec.Bucket)}
		d.Bytes(zr.OwnStaticSHA[:])
		d.Bytes(zr.OwnPacketSHA[:])
		if d.Err != nil {
			return nil, ErrBinding
		}
		a.zeroRef = zr
		p.persistentRefs = append(p.persistentRefs, *zr)
		a.z, err = incidence.ReadTriplesOwn(d, s.party, own.D, 1)
		if err != nil {
			return nil, err
		}
		if s.party == 0 {
			a.p0, err = aggregation.ReadPermPrep0Own(d, own.Stage0, imdbprod.AnchorObjects)
			a.stage0 = own.Stage0
		} else {
			a.p1, err = aggregation.ReadPermPrep1Own(d, own.Stage1, imdbprod.AnchorObjects)
		}
		if s.anchorStore != nil && own.Stage1 != nil {
			own.Stage1.Discard()
		}
		if err != nil {
			return nil, err
		}
	}
	var err error
	p.keep, err = aggregation.ReadComparisonOwn(d, s.party, imdbprod.AnchorObjects)
	if err != nil {
		return nil, err
	}
	if s.party == 0 {
		p.c0, err = aggregation.ReadCompaction0Own(d, s.payload.LayoutID, imdbprod.AnchorObjects, s.target.Manifest().TargetBucketBits)
	} else {
		p.c1, err = aggregation.ReadCompaction1Own(d, s.payload.LayoutID, imdbprod.AnchorObjects, s.target.Manifest().TargetBucketBits)
	}
	if err != nil {
		return nil, err
	}
	p.pe, err = targetpe.ReadPacketOwn(d, s.party, s.target.Lineage(), productionShape().G)
	if err != nil {
		return nil, err
	}
	capacities := []int{imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity}
	if inventoryV3 {
		p.position, err = targetposition.ReadInventoryOwn(d, s.party, s.target.Lineage(), capacities, imdbprod.PositionBin, imdbprod.PositionMax)
	} else {
		p.position, err = targetposition.ReadPacketOwn(d, s.party, s.target.Lineage(), capacities, imdbprod.PositionBin, imdbprod.PositionMax)
	}
	if err != nil {
		return nil, err
	}
	p.agg, err = targetaggregation.ReadPacketOwn(d, s.party, s.target.Lineage(), productionShapeForD(dTarget))
	if err != nil {
		return nil, err
	}
	return p, nil
}
