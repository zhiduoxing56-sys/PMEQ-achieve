package targetcrypto

import "testing"

func benchmarkKey(b *testing.B) MasterKey {
	b.Helper()
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		b.Fatalf("NewMasterKey: %v", err)
	}
	return key
}

func BenchmarkKJoin(b *testing.B) {
	key := benchmarkKey(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := KJoin(key, uint64(i)+1); err != nil {
			b.Fatalf("KJoin: %v", err)
		}
	}
}

func BenchmarkKWord(b *testing.B) {
	key := benchmarkKey(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := KWord(key, katQGram); err != nil {
			b.Fatalf("KWord: %v", err)
		}
	}
}

func BenchmarkJoinBucketComponent(b *testing.B) {
	key := benchmarkKey(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := JoinBucketComponent(key, uint64(i)+1, 14); err != nil {
			b.Fatalf("JoinBucketComponent: %v", err)
		}
	}
}

func BenchmarkWordBucketComponent(b *testing.B) {
	key := benchmarkKey(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := WordBucketComponent(key, katQGram, 14); err != nil {
			b.Fatalf("WordBucketComponent: %v", err)
		}
	}
}

func BenchmarkPartEval(b *testing.B) {
	joinScalar, err := KJoin(benchmarkKey(b), 42)
	if err != nil {
		b.Fatalf("KJoin: %v", err)
	}
	share := scalarShareFromScalar(joinScalar)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := PartEval(share); err != nil {
			b.Fatalf("PartEval: %v", err)
		}
	}
}

func BenchmarkPointCanonicalEncoding(b *testing.B) {
	target, err := DeriveTargetGroupPoint(benchmarkKey(b), 42, katQGram)
	if err != nil {
		b.Fatalf("DeriveTargetGroupPoint: %v", err)
	}
	left, _, err := SplitPoint(target)
	if err != nil {
		b.Fatalf("SplitPoint: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = left.CanonicalBytes()
	}
}

func BenchmarkSplitScalar(b *testing.B) {
	secret, err := KJoin(benchmarkKey(b), 42)
	if err != nil {
		b.Fatalf("KJoin: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := SplitScalar(secret); err != nil {
			b.Fatalf("SplitScalar: %v", err)
		}
	}
}

func BenchmarkSplitPoint(b *testing.B) {
	target, err := DeriveTargetGroupPoint(benchmarkKey(b), 42, katQGram)
	if err != nil {
		b.Fatalf("DeriveTargetGroupPoint: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := SplitPoint(target); err != nil {
			b.Fatalf("SplitPoint: %v", err)
		}
	}
}

func BenchmarkSplitBucketComponent(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := SplitBucketComponent(0x1234&0x3FFF, 14); err != nil {
			b.Fatalf("SplitBucketComponent: %v", err)
		}
	}
}
