package indexbuild

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestTargetArtifactRoundTripAndBinding(t *testing.T) {
	kb, kt := phase7bKeys(t)
	m, a, b, s, e := Build(nil, []AreaAliasRecord{{ID: 1, Area: 7, Name: "aaaaabcde"}}, kb, kt, 16, 16)
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := NewTargetManifest([16]byte{1}, m, s.Target)
	if e != nil {
		t.Fatal(e)
	}
	for party, p := range []PartyIndex{a, b} {
		var buf bytes.Buffer
		if e = WriteTargetParty(&buf, manifest, uint8(party), p); e != nil {
			t.Fatal(e)
		}
		if uint64(buf.Len()) != TargetEncodedBytes(uint64(len(p.TargetBuckets)), uint64(s.Target.LogicalGroups), uint64(s.Target.PaddedSlots)) {
			t.Fatal("encoded length")
		}
		raw := append([]byte(nil), buf.Bytes()...)
		decoded, e := ReadTargetParty(bytes.NewReader(raw), manifest, uint8(party))
		if e != nil || !reflect.DeepEqual(p, decoded) {
			t.Fatal("roundtrip", e)
		}
		for _, data := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
			if _, e = ReadTargetParty(bytes.NewReader(data), manifest, uint8(party)); e == nil {
				t.Fatal("truncation/trailing")
			}
		}
		if _, e = ReadTargetParty(bytes.NewReader(raw), manifest, uint8(1-party)); e == nil {
			t.Fatal("party mismatch")
		}
		changed := manifest
		changed.IndexID[0]++
		if _, e = ReadTargetParty(bytes.NewReader(raw), changed, uint8(party)); e == nil {
			t.Fatal("index mismatch")
		}
		changed = manifest
		changed.TargetBucketBits = 15
		if _, e = ReadTargetParty(bytes.NewReader(raw), changed, uint8(party)); e == nil {
			t.Fatal("width mismatch")
		}
	}
	raw, _ := json.Marshal(manifest)
	if _, e = ReadTargetManifest(bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	bad := manifest
	bad.Tiers[0] = 8
	raw, _ = json.Marshal(bad)
	if _, e = ReadTargetManifest(bytes.NewReader(raw)); e == nil {
		t.Fatal("tier mismatch")
	}
}
