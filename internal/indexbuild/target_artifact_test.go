package indexbuild

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTargetArtifactRoundTripAndBinding(t *testing.T) {
	kb, kt := phase7bKeys(t)
	for _, bits := range []int{14, 15, 16, 17} {
		m, a, b, s, e := Build(nil, []AreaAliasRecord{{ID: 1, Area: 7, Name: "aaaaabcde"}}, kb, kt, bits, bits)
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
			if uint64(buf.Len()) != TargetEncodedBytesForBits(uint8(bits), uint64(len(p.TargetBuckets)), uint64(s.Target.LogicalGroups), uint64(s.Target.PaddedSlots)) {
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
			changed.TargetBucketBits = uint8(bits ^ 1)
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
}

func TestTargetArtifactTier32768AndLegacyHeader(t *testing.T) {
	kb, kt := phase7bKeys(t)
	meta, p, _, stats, e := Build(nil, []AreaAliasRecord{{ID: 1, Area: 7, Name: "aaaa"}}, kb, kt, 16, 16)
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewTargetManifest([16]byte{2}, meta, stats.Target)
	if e != nil {
		t.Fatal(e)
	}
	m.Version = 1
	m.Tiers[8] = 0
	var encoded bytes.Buffer
	if e = WriteTargetParty(&encoded, m, 0, p); e != nil {
		t.Fatal(e)
	}
	var expected bytes.Buffer
	old := struct {
		Magic       [8]byte
		Version     uint32
		IndexID     [16]byte
		Party, Bits uint8
		Q           uint32
		Tiers       [8]uint32
		Buckets     uint32
	}{Magic: [8]byte{'P', 'M', 'E', 'Q', 'P', 'S', '0', '1'}, Version: 1, IndexID: m.IndexID, Party: 0, Bits: m.TargetBucketBits, Q: m.Q, Tiers: [8]uint32{4, 16, 64, 256, 1024, 4096, 8192, 16384}, Buckets: m.NonemptyBuckets}
	if e = binary.Write(&expected, binary.LittleEndian, old); e != nil {
		t.Fatal(e)
	}
	if expected.Len() != 70 || !bytes.Equal(expected.Bytes(), encoded.Bytes()[:70]) {
		t.Fatal("legacy physical header changed")
	}
	if _, e = ReadTargetParty(bytes.NewReader(encoded.Bytes()), m, 0); e != nil {
		t.Fatal(e)
	}
	meta, p, _, stats, e = Build(nil, []AreaAliasRecord{{ID: 1, Area: 7, Name: strings.Repeat("a", 32771)}}, kb, kt, 16, 16)
	if e != nil || stats.Target.RealSlots != 32768 || stats.Target.PaddedSlots != 32768 {
		t.Fatal("large tier", e, stats.Target)
	}
	m, e = NewTargetManifest([16]byte{3}, meta, stats.Target)
	if e != nil {
		t.Fatal(e)
	}
	encoded.Reset()
	if e = WriteTargetParty(&encoded, m, 0, p); e != nil {
		t.Fatal(e)
	}
	decoded, e := ReadTargetParty(bytes.NewReader(encoded.Bytes()), m, 0)
	if e != nil || !reflect.DeepEqual(p, decoded) {
		t.Fatal("32768 roundtrip", e)
	}
	m.Version = 1
	m.Tiers[8] = 0
	if e = WriteTargetParty(&bytes.Buffer{}, m, 0, p); e == nil {
		t.Fatal("old manifest accepted new tier")
	}
}
