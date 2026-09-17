package anchorfilter

// PositionToken contains the same masked bounds as the Anchor query, without DPF.
type PositionToken struct {
	PID                [16]byte
	Ltilde, RplusTilde uint32
}
