package aggregation

// RestoreDealerLayout is TRUSTED OFFLINE ONLY. IDs are the original sealed
// payload's gamma order, supplied by its owner, never reconstructed by a cloud.
func RestoreDealerLayout(layout [16]byte, ids []uint64) (*DealerLayout, error) {
	if layout == [16]byte{} || len(ids) != CandidateCount {
		return nil, ErrShape
	}
	d := &DealerLayout{LayoutID: layout, N: len(ids), gamma: map[uint64]uint32{}}
	for i, id := range ids {
		if _, ok := d.gamma[id]; ok {
			return nil, ErrShape
		}
		d.gamma[id] = uint32(i)
	}
	return d, nil
}
