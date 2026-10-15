// Package domain defines the distinct mathematical domains used by PMEQ's
// foundational sharing layer.
package domain

// Bit is an element of F_2. Its boolean representation makes invalid values
// such as 2 unrepresentable.
type Bit bool

const (
	BitZero Bit = false
	BitOne  Bit = true
)

// Add returns b+c in F_2.
func (b Bit) Add(c Bit) Bit { return b != c }

// Sub returns b-c in F_2. Addition and subtraction coincide in F_2.
func (b Bit) Sub(c Bit) Bit { return b != c }
