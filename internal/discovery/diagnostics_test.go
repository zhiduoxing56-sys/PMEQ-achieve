package discovery

import (
	"pmeq/internal/anchorfilter"
	"testing"
)

// These assertions reconcile execution counters with the physical wire and
// allocated triple dimensions, including an empty accessed bucket.
func TestAnchorDiagnosticsReconcile(t *testing.T) {
	for _, present := range []bool{false, true} {
		m := runDomainFixture(t, newDomainFixture(t, 7, present), domainBackend{})
		var total uint64
		for party, d := range m.AnchorDiagnostics {
			if len(d.Blocks) != 1 {
				t.Fatal("block count", d)
			}
			var anchorBytes uint64
			var operations AnchorOperations
			for _, b := range d.Blocks {
				if len(b.GroupPadWidths) != b.Groups || b.ReservedPositionSlots != b.PaddedSlots {
					t.Fatal("physical sizes", b)
				}
				tSlots, dims := uint64(b.PaddedSlots), uint64(b.ObjectCoordinates)
				if b.Position.Operations.SCMP != 2*tSlots || b.ValidityAND.Operations.BooleanProducts != 2*tSlots || b.HitB2A.Operations.B2AProducts != tSlots || b.Incidence.Operations.DenseProducts != tSlots*dims || b.ReservedDenseProducts != tSlots*dims || b.ObjectThreshold.Operations.SCMP != dims || b.ObjectB2A.Operations.B2AProducts != dims || b.Alignment.Operations.Permutations != 1 || b.Alignment.Operations.PermutationCoordinates != 7 {
					t.Fatal("executed operators", b)
				}
				if b.IndexMatch.Operations.DPFEvaluations != uint64(b.Groups) {
					t.Fatal("DPF invocations", b)
				}
				stages := []AnchorStage{b.IndexMatch, b.Position, b.ValidityAND, b.HitB2A, b.Incidence, b.ObjectThreshold, b.ObjectB2A, b.Alignment, b.Accumulation}
				for _, s := range stages {
					if s.Wall < 0 || s.TransportWait < 0 || s.TransportWait > s.Wall {
						t.Fatal("stage times", s)
					}
					anchorBytes += s.SentBytes
					operations.DPFEvaluations += s.Operations.DPFEvaluations
					operations.SCMP += s.Operations.SCMP
					operations.BooleanProducts += s.Operations.BooleanProducts
					operations.B2AProducts += s.Operations.B2AProducts
					operations.DenseProducts += s.Operations.DenseProducts
					operations.IncidenceChunks += s.Operations.IncidenceChunks
					operations.Permutations += s.Operations.Permutations
					operations.PermutationCoordinates += s.Operations.PermutationCoordinates
				}
				// Per party: D/T masked incidence values plus one 37-byte frame per chunk.
				if b.Incidence.SentBytes != tSlots*(dims+1)+37*b.Incidence.Operations.IncidenceChunks {
					t.Fatal("incidence wire", b)
				}
			}
			anchorBytes += d.FinalThreshold.SentBytes
			operations.SCMP += d.FinalThreshold.Operations.SCMP
			if d.FinalThreshold.Operations.SCMP != 7 || d.SentBytes != anchorBytes || d.Operations != operations || d.SentBytes != m.ServerPhaseBytes[party][0] {
				t.Fatal("anchor totals", d, anchorBytes, operations)
			}
			for _, v := range m.ServerPhaseBytes[party] {
				total += v
			}
		}
		if total != m.ServerBytes {
			t.Fatal("whole query byte reconciliation", total, m.ServerBytes)
		}
	}
}

var _ anchorfilter.SCMPBackend = domainBackend{}
