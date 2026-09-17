package codec

import (
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/internal/core"
)

const KeyBytes = core.KeyBytes

func EncodeKey(k dpf128.Key) []byte          { return core.Encode(k) }
func DecodeKey(b []byte) (dpf128.Key, error) { return core.Decode(b) }
