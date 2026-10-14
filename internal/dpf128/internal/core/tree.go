package core

import "pmeq/internal/domain"

type layerTrace struct {
	keepControl0 domain.Bit
	keepControl1 domain.Bit
	loseSeed0    Seed
	loseSeed1    Seed
	loseControl0 domain.Bit
	loseControl1 domain.Bit
}

func PointBit(point [16]byte, level int) domain.Bit {
	return domain.Bit((point[level/8]>>(7-(level%8)))&1 == 1)
}

func xorSeed(left, right Seed) (result Seed) {
	for i := range result {
		result[i] = left[i] ^ right[i]
	}
	return result
}

func selectChild(
	branch domain.Bit,
	left Seed,
	leftControl domain.Bit,
	right Seed,
	rightControl domain.Bit,
) (Seed, domain.Bit) {
	if branch == domain.BitZero {
		return left, leftControl
	}
	return right, rightControl
}

func correctedChild(seed Seed, control domain.Bit, parentControl domain.Bit, cw correctionWord, branch domain.Bit) (Seed, domain.Bit) {
	if parentControl == domain.BitZero {
		return seed, control
	}
	seed = xorSeed(seed, cw.seedCW)
	if branch == domain.BitZero {
		return seed, control.Add(cw.tcwLeft)
	}
	return seed, control.Add(cw.tcwRight)
}

func Generate(root0, root1 Seed, alpha [16]byte) (Key, Key) {
	key0, key1, _ := generateWithTrace(root0, root1, alpha)
	return key0, key1
}

func generateWithTrace(root0, root1 Seed, alpha [16]byte) (Key, Key, [Depth]layerTrace) {
	seed0, seed1 := root0, root1
	control0, control1 := domain.BitZero, domain.BitOne
	var corrections [Depth]correctionWord
	var trace [Depth]layerTrace

	for level := 0; level < Depth; level++ {
		parentControl0, parentControl1 := control0, control1
		alphaBit := PointBit(alpha, level)
		keep := alphaBit
		lose := alphaBit.Add(domain.BitOne)

		left0, leftControl0, right0, rightControl0 := Expand(seed0)
		left1, leftControl1, right1, rightControl1 := Expand(seed1)
		loseSeed0, loseControl0 := selectChild(lose, left0, leftControl0, right0, rightControl0)
		loseSeed1, loseControl1 := selectChild(lose, left1, leftControl1, right1, rightControl1)

		cw := correctionWord{
			seedCW:   xorSeed(loseSeed0, loseSeed1),
			tcwLeft:  leftControl0.Add(leftControl1).Add(alphaBit).Add(domain.BitOne),
			tcwRight: rightControl0.Add(rightControl1).Add(alphaBit),
		}
		corrections[level] = cw

		keepSeed0, keepControl0 := selectChild(keep, left0, leftControl0, right0, rightControl0)
		keepSeed1, keepControl1 := selectChild(keep, left1, leftControl1, right1, rightControl1)
		seed0, control0 = correctedChild(keepSeed0, keepControl0, parentControl0, cw, keep)
		seed1, control1 = correctedChild(keepSeed1, keepControl1, parentControl1, cw, keep)

		loseSeed0, loseControl0 = correctedChild(loseSeed0, loseControl0, parentControl0, cw, lose)
		loseSeed1, loseControl1 = correctedChild(loseSeed1, loseControl1, parentControl1, cw, lose)
		trace[level] = layerTrace{
			keepControl0: control0,
			keepControl1: control1,
			loseSeed0:    loseSeed0,
			loseSeed1:    loseSeed1,
			loseControl0: loseControl0,
			loseControl1: loseControl1,
		}
	}

	value0 := Convert(seed0)
	value1 := Convert(seed1)
	finalCW := domain.BitOne.Add(value0).Add(value1)
	return newKey(root0, domain.BitZero, corrections, finalCW),
		newKey(root1, domain.BitOne, corrections, finalCW), trace
}

func Evaluate(key Key, point [16]byte) domain.Bit {
	seed, control := key.rootSeed, key.rootControl
	for level := 0; level < Depth; level++ {
		parentControl := control
		left, leftControl, right, rightControl := Expand(seed)
		branch := PointBit(point, level)
		seed, control = selectChild(branch, left, leftControl, right, rightControl)
		seed, control = correctedChild(seed, control, parentControl, key.corrections[level], branch)
	}
	value := Convert(seed)
	if control == domain.BitOne {
		value = value.Add(key.finalCW)
	}
	return value
}
