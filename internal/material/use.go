package material

import "sync"

// UseGuard is shared by copies of one party's preprocessing handle. It stops
// copying or concurrent calls from reusing a mask; it is not a persistent bank.
type UseGuard struct {
	mu   sync.Mutex
	step uint8
}

func NewUseGuard() *UseGuard { return &UseGuard{} }

func (u *UseGuard) Fresh() bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.step == 0
}

func (u *UseGuard) Claim(step uint8) bool {
	if u == nil || step > 1 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.step != step {
		return false
	}
	u.step++
	return true
}
