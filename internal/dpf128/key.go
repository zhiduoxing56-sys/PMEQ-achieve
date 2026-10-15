package dpf128

import "pmeq/internal/dpf128/internal/core"

// Key is one cloud's opaque local evaluation key. Its protocol fields are
// unexported by the compiler-enforced nested core package.
type Key = core.Key
