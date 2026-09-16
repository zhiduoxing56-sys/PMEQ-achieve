// Package indexbuild implements the trusted data-owner, offline base-index
// construction path. Plaintext records and logical keys are confined here;
// the returned party indexes contain only public placement metadata and one
// party's shares.
package indexbuild

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const (
	areaColumns      = 14
	areaAliasColumns = 16
)

// AreaRecord is the trusted build-time projection of area(id,name).
type AreaRecord struct {
	ID   uint64
	Name string
}

// AreaAliasRecord is the trusted build-time projection of area_alias(id,name,area).
type AreaAliasRecord struct {
	ID   uint64
	Name string
	Area uint64
}

// InputStats classifies raw COPY rows at the trusted parser boundary. A usable
// row has all fields required by its logical projection. Empty names are
// usable but short; short names do not enter the main q=4 index.
type InputStats struct {
	RawRows          int
	UsableRows       int
	NullNames        int
	NullJoinValues   int
	EmptyNames       int
	ShortNames       int
	IndexedRecords   int
	QGramOccurrences int
}

// ParseCOPYTextLine parses one PostgreSQL COPY text row. A nil field denotes
// the raw, unescaped null marker \N. Tabs delimit fields before unescaping.
func ParseCOPYTextLine(line []byte) ([]*string, error) {
	var fields []*string
	start := 0
	for i := 0; i <= len(line); i++ {
		if i != len(line) && line[i] != '\t' {
			continue
		}
		raw := line[start:i]
		if len(raw) == 2 && raw[0] == '\\' && raw[1] == 'N' {
			fields = append(fields, nil)
		} else {
			decoded, err := unescapeCOPYText(raw)
			if err != nil {
				return nil, fmt.Errorf("field %d: %w", len(fields), err)
			}
			value := string(decoded)
			fields = append(fields, &value)
		}
		start = i + 1
	}
	return fields, nil
}

func unescapeCOPYText(raw []byte) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return nil, errors.New("dangling backslash escape")
		}
		switch raw[i] {
		case '\\':
			out = append(out, '\\')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			value := int(raw[i] - '0')
			for n := 1; n < 3 && i+1 < len(raw) && raw[i+1] >= '0' && raw[i+1] <= '7'; n++ {
				i++
				value = value*8 + int(raw[i]-'0')
			}
			if value > 255 {
				return nil, errors.New("octal escape exceeds one byte")
			}
			out = append(out, byte(value))
		case 'x':
			value, digits := 0, 0
			for digits < 2 && i+1 < len(raw) {
				nibble, ok := hexNibble(raw[i+1])
				if !ok {
					break
				}
				i++
				digits++
				value = value*16 + nibble
			}
			if digits == 0 {
				return nil, errors.New("hex escape has no digits")
			}
			out = append(out, byte(value))
		default:
			return nil, fmt.Errorf("illegal escape \\%c", raw[i])
		}
	}
	return out, nil
}

func hexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	default:
		return 0, false
	}
}

// LoadArea reads up to limit valid projected rows; limit <= 0 means no limit.
// Rows whose projected name is NULL are not logical records.
func LoadArea(r io.Reader, limit int) ([]AreaRecord, error) {
	records, _, err := LoadAreaWithStats(r, limit)
	return records, err
}

// LoadAreaWithStats is LoadArea plus complete raw/input classification.
func LoadAreaWithStats(r io.Reader, limit int) ([]AreaRecord, InputStats, error) {
	var records []AreaRecord
	var stats InputStats
	err := scanCOPY(r, areaColumns, func(line int, fields []*string) error {
		stats.RawRows++
		if fields[0] == nil {
			return fmt.Errorf("line %d: area.id is NULL", line)
		}
		if fields[2] == nil {
			stats.NullNames++
			return nil
		}
		if !utf8.ValidString(*fields[2]) {
			return fmt.Errorf("line %d: area.name is not valid UTF-8", line)
		}
		id, err := strconv.ParseUint(*fields[0], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: area.id: %w", line, err)
		}
		name := *fields[2]
		records = append(records, AreaRecord{ID: id, Name: name})
		classifyName(name, &stats)
		return nil
	}, func() bool { return limit > 0 && len(records) >= limit })
	return records, stats, err
}

// LoadAreaAlias reads up to limit valid projected rows; limit <= 0 means no
// limit. Rows with a NULL name or join value are not logical records.
func LoadAreaAlias(r io.Reader, limit int) ([]AreaAliasRecord, error) {
	records, _, err := LoadAreaAliasWithStats(r, limit)
	return records, err
}

// LoadAreaAliasWithStats is LoadAreaAlias plus complete raw/input classification.
func LoadAreaAliasWithStats(r io.Reader, limit int) ([]AreaAliasRecord, InputStats, error) {
	var records []AreaAliasRecord
	var stats InputStats
	err := scanCOPY(r, areaAliasColumns, func(line int, fields []*string) error {
		stats.RawRows++
		if fields[0] == nil {
			return fmt.Errorf("line %d: area_alias.id is NULL", line)
		}
		if fields[2] == nil {
			stats.NullNames++
			return nil
		}
		if fields[1] == nil {
			stats.NullJoinValues++
			return nil
		}
		if !utf8.ValidString(*fields[2]) {
			return fmt.Errorf("line %d: area_alias.name is not valid UTF-8", line)
		}
		id, err := strconv.ParseUint(*fields[0], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: area_alias.id: %w", line, err)
		}
		area, err := strconv.ParseUint(*fields[1], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: area_alias.area: %w", line, err)
		}
		name := *fields[2]
		records = append(records, AreaAliasRecord{ID: id, Name: name, Area: area})
		classifyName(name, &stats)
		return nil
	}, func() bool { return limit > 0 && len(records) >= limit })
	return records, stats, err
}

func classifyName(name string, stats *InputStats) {
	stats.UsableRows++
	if name == "" {
		stats.EmptyNames++
	}
	runes := len([]rune(name))
	if runes < Q {
		stats.ShortNames++
		return
	}
	stats.IndexedRecords++
	stats.QGramOccurrences += runes - Q + 1
}

func scanCOPY(r io.Reader, columns int, visit func(int, []*string) error, done func() bool) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		fields, err := ParseCOPYTextLine(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if len(fields) != columns {
			return fmt.Errorf("line %d: got %d columns, want %d", line, len(fields), columns)
		}
		if err := visit(line, fields); err != nil {
			return err
		}
		if done() {
			return nil
		}
	}
	return scanner.Err()
}
