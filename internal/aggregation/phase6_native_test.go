//go:build phase6native

package aggregation

import "pmeq/internal/scmpnative"

func init() { compositionSCMP = scmpnative.Backend{} }
