package incidence

import (
	"math/rand"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"reflect"
	"testing"
)

func recoverShare(a, b Share) Z128 { return a.Value().Add(b.Value()) }
func TestZ128(t *testing.T) {
	for a := 0; a < 128; a++ {
		for b := 0; b < 128; b++ {
			x, y := Z128(a), Z128(b)
			if int(x.Add(y)) != (a+b)%128 || int(x.Sub(y)) != (a-b+128)%128 || int(x.Mul(y)) != (a*b)%128 {
				t.Fatal("ring")
			}
		}
	}
	for i := 0; i < 128; i++ {
		a, b, e := Split(Z128(i))
		if e != nil || recoverShare(a, b) != Z128(i) {
			t.Fatal("sharing", e)
		}
	}
}
func TestB2ATruthTableAnd100000(t *testing.T) {
	rng := rand.New(rand.NewSource(5101))
	n := 100004
	x := [2][]share.BitShare{make([]share.BitShare, n), make([]share.BitShare, n)}
	for i := 0; i < n; i++ {
		a, b := rng.Intn(2), rng.Intn(2)
		if i < 4 {
			a, b = i/2, i%2
		}
		x[0][i] = share.NewBitShare(domain.Bit(a == 1))
		x[1][i] = share.NewBitShare(domain.Bit(b == 1))
	}
	p, q, e := Preprocess(n, 1)
	if e != nil {
		t.Fatal(e)
	}
	a, ma, e := BeginB2A(x[0], p)
	if e != nil {
		t.Fatal(e)
	}
	b, mb, e := BeginB2A(x[1], q)
	if e != nil {
		t.Fatal(e)
	}
	o, e := OpenMasked(ma, mb)
	if e != nil {
		t.Fatal(e)
	}
	u, e := a.Finish(o)
	if e != nil {
		t.Fatal(e)
	}
	v, e := b.Finish(o)
	if e != nil {
		t.Fatal(e)
	}
	for i := range u {
		want := Z128(0)
		if x[0][i].Value() != x[1][i].Value() {
			want = 1
		}
		if recoverShare(u[i], v[i]) != want {
			t.Fatalf("case %d", i)
		}
	}
	if _, _, e = BeginB2A(x[0], p); e != ErrConsumed {
		t.Fatal("reused preprocessing")
	}
	if _, e = a.Finish(o); e != ErrConsumed {
		t.Fatal("repeat finish")
	}
}

func TestHiddenMappingView(t *testing.T) {
	slots := []Posting{{1, true}, {2, true}, {1, true}, {3, true}, {2, true}, {1, true}, {0, false}}
	seen := [2][128]bool{}
	equal, unit := 0, 0
	for trial := 0; trial < 4096; trial++ {
		l, e := PrepareLayout(slots)
		if e != nil {
			t.Fatal(e)
		}
		p, q, e := ShareIncidence(l)
		if e != nil {
			t.Fatal(e)
		}
		if l.D != 4 || l.Coordinates[0] != l.Coordinates[2] || l.Coordinates[0] != l.Coordinates[5] || l.Coordinates[1] != l.Coordinates[4] {
			t.Fatal("DO layout")
		}
		for party, state := range []*PartyMatrix{p, q} {
			seen[party][state.coefficients[0]] = true
			if reflect.DeepEqual(state.coefficients[:4], state.coefficients[8:12]) {
				equal++
			}
			nz := 0
			for _, v := range state.coefficients[:4] {
				if v != 0 {
					nz++
				}
			}
			if nz == 1 {
				unit++
			}
		}
		for s, j := range l.Coordinates {
			for k := 0; k < l.D; k++ {
				v := p.coefficients[s*l.D+k].Add(q.coefficients[s*l.D+k])
				want := Z128(0)
				if j == k {
					want = 1
				}
				if v != want {
					t.Fatal("incidence coefficient")
				}
			}
		}
	}
	// Statistical regression only, not a proof and not a demand that all shares differ.
	if equal > 16 || unit > 16 {
		t.Fatal("readable deterministic row signal", equal, unit)
	}
	for _, hist := range seen {
		for _, ok := range hist {
			if !ok {
				t.Fatal("marginal mask support")
			}
		}
	}
	typ := reflect.TypeOf(PartyMatrix{})
	if typ.NumField() != 3 || typ.Field(0).Name != "D" || typ.Field(1).Name != "T" || typ.Field(2).Name != "coefficients" {
		t.Fatal("party schema")
	}
	t.Logf("single-party trials=4096 per party equal_columns=%d unit_columns=%d; all 128 marginal values observed", equal, unit)
}

func TestStreamingAndEdges(t *testing.T) {
	slots := []Posting{{1, true}, {2, true}, {1, true}, {3, true}, {2, true}, {1, true}, {0, false}}
	l, e := PrepareLayout(slots)
	if e != nil {
		t.Fatal(e)
	}
	p, q, e := ShareIncidence(l)
	if e != nil {
		t.Fatal(e)
	}
	for _, chunk := range []int{1, 2, 4, 32} {
		a, _ := NewAggregator(0, p, chunk)
		b, _ := NewAggregator(1, q, chunk)
		for off := 0; off < len(slots); off += chunk {
			n := min(chunk, len(slots)-off)
			u, v, e := Preprocess(n, l.D)
			if e != nil {
				t.Fatal(e)
			}
			x, y := make([]Share, n), make([]Share, n)
			for i := range x {
				x[i], y[i], e = Split(1)
				if e != nil {
					t.Fatal(e)
				}
			}
			ma, e := a.BeginChunk(x, u)
			if e != nil {
				t.Fatal(e)
			}
			mb, e := b.BeginChunk(y, v)
			if e != nil {
				t.Fatal(e)
			}
			o, e := OpenMasked(ma, mb)
			if e != nil {
				t.Fatal(e)
			}
			if e = a.FinishChunk(o); e != nil {
				t.Fatal(e)
			}
			if e = b.FinishChunk(o); e != nil {
				t.Fatal(e)
			}
		}
		x, e := a.Result()
		if e != nil {
			t.Fatal(e)
		}
		y, e := b.Result()
		if e != nil {
			t.Fatal(e)
		}
		want := make([]Z128, l.D)
		for _, j := range l.Coordinates {
			if j >= 0 {
				want[j]++
			}
		}
		for j := range want {
			if recoverShare(x[j], y[j]) != want[j] {
				t.Fatal("F", chunk, j)
			}
		}
	}
	l, e = PrepareLayout([]Posting{{0, false}})
	if e != nil {
		t.Fatal(e)
	}
	p, _, e = ShareIncidence(l)
	if e != nil || p.D != 0 {
		t.Fatal("dummy-only", e)
	}
	a, _ := NewAggregator(0, p, 1)
	if x, e := a.Result(); e != nil || len(x) != 0 {
		t.Fatal("empty", e)
	}
	if _, _, e = ShareIncidence(DealerLayout{D: 4, Coordinates: []int{4}}); e == nil {
		t.Fatal("bad coordinate")
	}
	if _, _, e = Preprocess(-1, 4); e == nil {
		t.Fatal("negative")
	}
	if _, e = NewAggregator(2, p, 1); e == nil {
		t.Fatal("party")
	}
}

func TestOnlineStateGraphAndChunkGuards(t *testing.T) {
	forbidden := map[reflect.Type]bool{reflect.TypeOf(DealerLayout{}): true, reflect.TypeOf(Posting{}): true}
	visited := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		if forbidden[typ] {
			t.Fatalf("DO state reachable from online graph: %v", typ)
		}
		if visited[typ] {
			return
		}
		visited[typ] = true
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				switch f.Name {
				case "RecordID", "Coordinates", "PeerShare", "BothShares", "phi", "rho":
					t.Fatalf("forbidden party field %s", f.Name)
				}
				walk(f.Type)
			}
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(PartyMatrix{}), reflect.TypeOf(PartyTriples{}), reflect.TypeOf(B2A{}), reflect.TypeOf(Aggregator{})} {
		walk(typ)
	}
	l, e := PrepareLayout([]Posting{{1, true}, {1, true}})
	if e != nil {
		t.Fatal(e)
	}
	p, _, e := ShareIncidence(l)
	if e != nil {
		t.Fatal(e)
	}
	a, e := NewAggregator(0, p, 1)
	if e != nil {
		t.Fatal(e)
	}
	tr, _, e := Preprocess(2, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.BeginChunk([]Share{NewShare(0), NewShare(0)}, tr); e != ErrShape {
		t.Fatal("chunk limit")
	}
	if _, e = a.Result(); e != ErrConsumed {
		t.Fatal("incomplete result")
	}
	if e = a.FinishChunk(Opened{}); e != ErrConsumed {
		t.Fatal("finish without begin")
	}
	tr, _, e = Preprocess(1, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.BeginChunk([]Share{NewShare(0)}, tr); e != nil {
		t.Fatal(e)
	}
	if _, e = a.BeginChunk([]Share{NewShare(0)}, tr); e != ErrConsumed {
		t.Fatal("reused chunk")
	}
	if e = a.FinishChunk(Opened{}); e != ErrShape {
		t.Fatal("opening length")
	}
}
