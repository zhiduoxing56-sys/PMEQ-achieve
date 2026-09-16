package aggregation

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand"
	"pmeq/internal/incidence"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// Independent unbuffered reference checks the PRG stream, endianness and
// rejection convention, including crossing the production buffer boundary.
func referenceExpansion(t *testing.T, seed [32]byte, n int) []uint32 {
	b, e := aes.NewCipher(seed[:])
	must(t, e)
	reader := &cipher.StreamReader{S: cipher.NewCTR(b, []byte("PMEQ-RHO-PRG-V1!")), R: zeroReader{}}
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(i)
	}
	for i := n - 1; i > 0; i-- {
		bound := uint64(i + 1)
		minimum := (uint64(1) << 32) % bound
		var v uint64
		for {
			var raw [4]byte
			_, e = io.ReadFull(reader, raw[:])
			must(t, e)
			v = uint64(binary.LittleEndian.Uint32(raw[:]))
			if v >= minimum {
				break
			}
		}
		j := int(v % bound)
		out[i], out[j] = out[j], out[i]
	}
	return out
}
func TestSeedExpansionDefinition(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, n := range []int{0, 1, 16, 4096, 120071} {
		a, e := ExpandRho(seed, n)
		must(t, e)
		if !reflect.DeepEqual(a, referenceExpansion(t, seed, n)) {
			t.Fatal("stream mismatch", n)
		}
		if n == 16 {
			want := []uint32{2, 13, 11, 3, 12, 10, 15, 7, 0, 9, 8, 5, 6, 14, 4, 1}
			if !reflect.DeepEqual(a, want) {
				t.Fatal("rho PRG version-1 KAT")
			}
			t.Logf("seed 00..1f N=16: %v", a)
		}
	}
	if _, e := ExpandRho(seed, -1); e == nil {
		t.Fatal("negative N")
	}
}

func TestStaticCompactFactorsReusable(t *testing.T) {
	pi, e := permutation(129)
	must(t, e)
	p, q, e := SplitPermutation([16]byte{5, 3}, 17, pi)
	must(t, e)
	seed := p.RhoSeed
	snapshot := append([]uint32(nil), q.sigma...)
	for invocation := 0; invocation < 32; invocation++ {
		a, b, e := PreprocessPermutation(p, q)
		must(t, e)
		x, y := make([]incidence.Share, 129), make([]incidence.Share, 129)
		for i := range x {
			x[i], y[i], e = incidence.Split(incidence.Z128((i + invocation) & 127))
			must(t, e)
		}
		d1, e := b.Message1(y)
		must(t, e)
		d2, y0, e := p.Message2(a, x, d1)
		must(t, e)
		y1, e := q.Finish(b, d2)
		must(t, e)
		for i, j := range pi {
			if y0[int(j)].Value().Add(y1[int(j)].Value()) != incidence.Z128((i+invocation)&127) {
				t.Fatal("static reuse")
			}
		}
	}
	if seed != p.RhoSeed || !reflect.DeepEqual(snapshot, q.sigma) {
		t.Fatal("static mutation")
	}
	q.BucketID++
	if _, _, e = PreprocessPermutation(p, q); e == nil {
		t.Fatal("bucket binding")
	}
}

func TestSeededPermutationAlgebra100000(t *testing.T) {
	rng := rand.New(rand.NewSource(503))
	for trial := 0; trial < 100000; trial++ {
		n := 1 + rng.Intn(256)
		if trial%10000 == 0 {
			n = 120071
		}
		pi, e := permutation(n)
		must(t, e)
		p, q, e := SplitPermutation([16]byte{5, 3}, uint16(trial), pi)
		must(t, e)
		rho, e := ExpandRho(p.RhoSeed, n)
		must(t, e)
		again, e := ExpandRho(p.RhoSeed, n)
		must(t, e)
		if !validPermutation(rho) || !validPermutation(q.sigma) || !reflect.DeepEqual(rho, again) {
			t.Fatal("invalid or nondeterministic permutation", trial)
		}
		for i, j := range rho {
			if q.sigma[int(j)] != pi[i] {
				t.Fatal("sigma[rho[i]] != pi[i]", trial, i)
			}
		}
	}
	t.Log("100000 fresh random pi/rho pairs, including 10 at N=120071: zero errors")
}

func TestCompactStaticSchemas(t *testing.T) {
	if reflect.TypeOf(Stage0{}).NumField() != 3 || reflect.TypeOf(Stage1{}).NumField() != 3 {
		t.Fatal("static fields")
	}
	if reflect.TypeOf(Stage0{}.RhoSeed) != reflect.TypeOf([32]byte{}) || reflect.TypeOf(Stage1{}.sigma) != reflect.TypeOf([]uint32{}) {
		t.Fatal("representation")
	}
	if reflect.TypeOf(DealerLayout{}.gamma).Elem().Kind() != reflect.Uint32 {
		t.Fatal("gamma coordinate type")
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(Stage0{}), reflect.TypeOf(Stage1{})} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() != reflect.Uint32 {
				t.Fatal("wide/static coordinate", field)
			}
		}
	}
	n, b := uint64(120071), uint64(53383)
	old := 16 * n * b
	cs0, cs1 := 32*b, 4*n*b
	t.Logf("factor bytes per bucket old=%d cs0=%d cs1=%d combined=%d; totals old=%d cs0=%d cs1=%d combined=%d reduction=%.9f", 16*n, 32, 4*n, 32+4*n, old, cs0, cs1, cs0+cs1, float64(old)/float64(cs0+cs1))
	t.Logf("Go headers Stage0=%d Stage1=%d; inclusive object+backing total=%d", unsafe.Sizeof(Stage0{}), unsafe.Sizeof(Stage1{}), b*(uint64(unsafe.Sizeof(Stage0{}))+uint64(unsafe.Sizeof(Stage1{}))+4*n))
}

func TestOfflinePoolAccountingAndConsumption(t *testing.T) {
	shape := OfflineShape{Products: 35968, PostingSlots: 332, LocalCoordinates: 160, Chunks: 2, GlobalRecords: 120071}
	size, e := shape.OfflineBytes(284)
	must(t, e)
	if size != 70120013 {
		t.Fatal(size)
	}
	total, e := (PoolConfig{3}).PoolStorage(size)
	must(t, e)
	if total != 3*size {
		t.Fatal(total)
	}
	if _, e = (PoolConfig{^uint64(0)}).PoolStorage(2); e == nil {
		t.Fatal("overflow")
	}
	id, e := NewPacketID()
	must(t, e)
	p := NewPartyPool([16]byte{1}, PoolConfig{1})
	if e = p.Consume(id); e == nil {
		t.Fatal("consume unsealed")
	}
	must(t, p.Provision(id))
	if e = p.Provision(id); e == nil {
		t.Fatal("capacity/repeated packet")
	}
	p.Seal()
	must(t, p.Consume(id))
	if p.Remaining() != 0 {
		t.Fatal("remaining")
	}
	if e = p.Consume(id); e == nil {
		t.Fatal("reused packet")
	}
	if e = p.Provision(id); e == nil {
		t.Fatal("online refill")
	}
}

func TestCompactPermutationBenchmark(t *testing.T) {
	n := 120071
	pi, e := permutation(n)
	must(t, e)
	p, q, e := SplitPermutation([16]byte{}, 42, pi)
	must(t, e)
	x, y := make([]incidence.Share, n), make([]incidence.Share, n)
	for _, r := range []int{1, 2, 4, 6} {
		expansions, onlines, allocs := []float64{}, []float64{}, []uint64{}
		heapDeltas := []uint64{}
		var gcCycles uint32
		for run := 0; run < 12; run++ {
			var expansion, online time.Duration
			var peakLive uint64
			var peakHeap uint64
			for h := 0; h < r; h++ {
				a, b, e := PreprocessPermutation(p, q)
				must(t, e)
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				st := time.Now()
				expanded, e := p.Expand(n)
				must(t, e)
				expansion += time.Since(st)
				st = time.Now()
				d1, e := b.Message1(y)
				must(t, e)
				d2, y0, e := expanded.Message2(a, x, d1)
				must(t, e)
				y1, e := q.Finish(b, d2)
				must(t, e)
				online += time.Since(st)
				runtime.ReadMemStats(&after)
				gcCycles += after.NumGC - before.NumGC
				if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc > peakHeap {
					peakHeap = after.HeapAlloc - before.HeapAlloc
				}
				runtime.KeepAlive(expanded)
				runtime.KeepAlive(d1)
				runtime.KeepAlive(d2)
				if after.TotalAlloc-before.TotalAlloc > peakLive {
					peakLive = after.TotalAlloc - before.TotalAlloc
				}
				for i := range y0 {
					if y0[i].Value().Add(y1[i].Value()) != 0 {
						t.Fatal("benchmark correctness")
					}
				}
			}
			if run >= 2 {
				expansions = append(expansions, float64(expansion)/1e6)
				onlines = append(onlines, float64(online)/1e6)
				allocs = append(allocs, peakLive)
				heapDeltas = append(heapDeltas, peakHeap)
			}
		}
		t.Logf("COMPACT r=%d N=%d expansion_ms=%v online_excluding_expansion_ms=%v per_invocation_allocated_bytes=%v rho_backing_bytes=%d wire_bytes=%d", r, n, expansions, onlines, allocs, 4*n, 2*n*r)
		t.Logf("TEMP r=%d peak_heap_increment_bytes=%v GC_cycles_inside_measured_windows=%d", r, heapDeltas, gcCycles)
	}
}
