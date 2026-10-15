package qgram

import "testing"

func TestIMDbFourQLengthsAndCodepointPositions(t *testing.T) {
	text := "电影🎥Cafe\u0301ǽאב"
	r := []rune(text)
	for _, q := range []int{3, 4, 5, 6} {
		all, e := Overlapping(text, q)
		if e != nil || len(all) != len(r)-q+1 {
			t.Fatal(q, e, all)
		}
		for p, c := range all {
			if c.Position != uint32(p) || c.Word != string(r[p:p+q]) {
				t.Fatal("codepoint drift", q, p)
			}
		}
		query, e := Query(text, q, 1)
		if e != nil || query[0] != all[0] {
			t.Fatal("query/index q mismatch", q, e)
		}
		long := ""
		for i := 0; i < 273; i++ {
			long += "🎥"
		}
		all, e = Overlapping(long, q)
		if e != nil || all[len(all)-1].Position != uint32(273-q) {
			t.Fatal("last position", q, e)
		}
		query, e = Query(long, q, 4)
		if e != nil || len(query) != 4 || query[3].Position != uint32(3*q) {
			t.Fatal("fixed r", q, e)
		}
	}
	if _, e := Query("short", 6, 4); e == nil {
		t.Fatal("insufficient chunks accepted")
	}
	if _, e := Overlapping(string([]byte{255}), 4); e == nil {
		t.Fatal("invalid UTF8 accepted")
	}
}
