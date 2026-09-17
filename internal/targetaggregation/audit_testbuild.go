//go:build phase10audit

// This file is an explicitly opt-in trusted correctness-oracle instrument.
// It is not part of the production build or a cloud deployment.
package targetaggregation

import "sync"

var auditLock sync.RWMutex
var auditSink func([16]byte, uint8, string, any)

func SetAuditSinkForTesting(f func([16]byte, uint8, string, any)) {
	auditLock.Lock()
	defer auditLock.Unlock()
	auditSink = f
}
func auditStage(q [16]byte, p uint8, name string, v any) {
	auditLock.RLock()
	defer auditLock.RUnlock()
	if auditSink != nil {
		auditSink(q, p, name, v)
	}
}
