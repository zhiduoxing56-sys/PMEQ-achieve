package discovery

import "time"

// Each counter is a completed invocation at one party. For a logical two-party
// comparison/multiplication, do not sum the two parties' identical counts.
type AnchorOperations struct {
	DPFEvaluations, SCMP, BooleanProducts, B2AProducts uint64
	Permutations, PermutationCoordinates, GFProducts                                   uint64
}

func (a AnchorOperations) subtract(b AnchorOperations) AnchorOperations {
	return AnchorOperations{a.DPFEvaluations - b.DPFEvaluations, a.SCMP - b.SCMP, a.BooleanProducts - b.BooleanProducts, a.B2AProducts - b.B2AProducts, a.Permutations - b.Permutations, a.PermutationCoordinates - b.PermutationCoordinates, a.GFProducts - b.GFProducts}
}

// SentBytes includes the 37-byte application frame; TransportWait is time spent
// inside the local byte channel exchange, overlapping the other party's work.
// Wall includes serialization, allocation, GC and waits. These are not CPU times.
type AnchorStage struct {
	Wall, TransportWait time.Duration
	SentBytes           uint64
	Frames              uint32
	Operations          AnchorOperations
}
type AnchorBlock struct {
	Block                                                                                                                           int
	Bucket                                                                                                                          uint32
	Groups, PaddedSlots, ObjectCoordinates, GlobalCoordinates                                                                       int
	GroupPadWidths                                                                                                                  []uint32
	ReservedPositionSlots, ReservedBooleanProducts, ReservedObjectB2A                                               int
	ReservedGFProducts                                                                                       uint64
	MaterialBinding, IndexMatch, Position, ValidityAND, ZeroPolynomial, ObjectB2A, Alignment, Accumulation AnchorStage
}
type AnchorDiagnostics struct {
	Blocks                   []AnchorBlock
	FinalThreshold           AnchorStage
	ReservedFinalComparisons int
	SentBytes                uint64
	Operations               AnchorOperations
}
type anchorMark struct {
	started time.Time
	wait    time.Duration
	sent    uint64
	frames  uint32
	ops     AnchorOperations
}

func (s *endpoint) mark() anchorMark {
	return anchorMark{time.Now(), s.wait, s.sent, s.seq, s.operations}
}
func (s *endpoint) since(m anchorMark) AnchorStage {
	return AnchorStage{time.Since(m.started), s.wait - m.wait, s.sent - m.sent, s.seq - m.frames, s.operations.subtract(m.ops)}
}
