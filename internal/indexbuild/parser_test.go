package indexbuild

import (
	"strings"
	"testing"
)

func TestParseCOPYTextLine(t *testing.T) {
	line := []byte("\\N\t\tleft\\tright\tline\\nnext\tslash\\\\end\t\\b\\f\\r\\v\t\\101\\x42\t世界")
	got, err := ParseCOPYTextLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != nil {
		t.Fatal("raw \\N was not NULL")
	}
	want := []string{"", "left\tright", "line\nnext", "slash\\end", "\b\f\r\v", "AB", "世界"}
	for i, value := range want {
		if got[i+1] == nil || *got[i+1] != value {
			t.Fatalf("field %d = %v, want %q", i+1, got[i+1], value)
		}
	}
}

func TestParseCOPYTextLineRejectsIllegalEscapes(t *testing.T) {
	for _, input := range []string{"abc\\", "\\q", "\\x", "\\400"} {
		if _, err := ParseCOPYTextLine([]byte(input)); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestLogicalProjectionAndExactColumns(t *testing.T) {
	areaFields := make([]string, areaColumns)
	areaFields[0] = "42"
	areaFields[2] = "A\\t世界"
	areas, err := LoadArea(strings.NewReader(strings.Join(areaFields, "\t")+"\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(areas) != 1 || areas[0] != (AreaRecord{42, "A\t世界"}) {
		t.Fatalf("area projection = %#v", areas)
	}

	aliasFields := make([]string, areaAliasColumns)
	aliasFields[0] = "7"
	aliasFields[1] = "42"
	aliasFields[2] = "别名"
	aliases, err := LoadAreaAlias(strings.NewReader(strings.Join(aliasFields, "\t")+"\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 1 || aliases[0] != (AreaAliasRecord{7, "别名", 42}) {
		t.Fatalf("alias projection = %#v", aliases)
	}
	if _, err := LoadArea(strings.NewReader("1\tx\ty\n"), 0); err == nil {
		t.Fatal("accepted wrong area column count")
	}
	if _, err := LoadAreaAlias(strings.NewReader("1\t2\tx\n"), 0); err == nil {
		t.Fatal("accepted wrong alias column count")
	}
}

func TestProjectedTextMustBeUTF8(t *testing.T) {
	fields := make([]string, areaColumns)
	fields[0] = "1"
	fields[2] = "\\xff"
	if _, err := LoadArea(strings.NewReader(strings.Join(fields, "\t")+"\n"), 0); err == nil {
		t.Fatal("accepted invalid UTF-8 name")
	}
}
