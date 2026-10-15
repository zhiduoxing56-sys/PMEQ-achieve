package dpf128_test

import (
	"testing"

	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/gen"
	"pmeq/internal/share"
)

var benchmarkSink share.BitShare
var benchmarkKey dpf128.Key

func BenchmarkGen(b *testing.B) {
	alpha := dpf128.Point{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key0, _, err := gen.Gen(alpha)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkKey = key0
	}
}

func BenchmarkEvalPoint(b *testing.B) {
	benchmarkEvalBucket(b, 1)
}

func BenchmarkEvalBucket19(b *testing.B)   { benchmarkEvalBucket(b, 19) }
func BenchmarkEvalBucket26(b *testing.B)   { benchmarkEvalBucket(b, 26) }
func BenchmarkEvalBucket33(b *testing.B)   { benchmarkEvalBucket(b, 33) }
func BenchmarkEvalBucket256(b *testing.B)  { benchmarkEvalBucket(b, 256) }
func BenchmarkEvalBucket1024(b *testing.B) { benchmarkEvalBucket(b, 1024) }

func benchmarkEvalBucket(b *testing.B, size int) {
	alpha := dpf128.Point{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key0, _, err := gen.Gen(alpha)
	if err != nil {
		b.Fatal(err)
	}
	points := make([]dpf128.Point, size)
	for i := range points {
		points[i] = alpha
		points[i][14] ^= byte(i)
		points[i][15] ^= byte(i >> 8)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result share.BitShare
		for _, point := range points {
			result = dpf128.Eval(key0, point)
		}
		benchmarkSink = result
	}
}
