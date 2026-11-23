package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// CanonicalJSON serializes v into deterministic ECMA-262 canonical JSON
// matching Beryl kernel's C++ CanonicalJsonWithoutChecksum (no HTML escaping,
// sorted object keys, no whitespace, integer-valued floats without .0).
func CanonicalJSON(v any) (string, error) {
	// Convert structs cleanly into generic JSON value tree preserving exact numbers.
	raw, err := marshalNoHTML(v)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := appendCanonicalValue(&sb, parsed); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ComputeChecksum computes SHA-256 hex of CanonicalJSON(data without "checksum").
func ComputeChecksum(v any) (string, error) {
	raw, err := marshalNoHTML(v)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return "", err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return "", fmt.Errorf("fingerprint root must be a JSON object")
	}
	delete(obj, "checksum")
	var sb strings.Builder
	if err := appendCanonicalValue(&sb, obj); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:]), nil
}

func marshalNoHTML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func appendCanonicalValue(sb *strings.Builder, v any) error {
	switch val := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if val {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		appendEcmaString(sb, val)
	case json.Number:
		s := val.String()
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			sb.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			sb.WriteString("null")
			return nil
		}
		appendCanonicalFloat(sb, f)
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			sb.WriteString("null")
			return nil
		}
		appendCanonicalFloat(sb, val)
	case int:
		sb.WriteString(strconv.Itoa(val))
	case int64:
		sb.WriteString(strconv.FormatInt(val, 10))
	case []any:
		sb.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := appendCanonicalValue(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			appendEcmaString(sb, k)
			sb.WriteByte(':')
			if err := appendCanonicalValue(sb, val[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", v)
	}
	return nil
}

func appendCanonicalFloat(sb *strings.Builder, f float64) {
	if f == 0 {
		sb.WriteByte('0')
		return
	}
	if math.Trunc(f) == f && f >= -9007199254740991 && f <= 9007199254740991 {
		sb.WriteString(strconv.FormatInt(int64(f), 10))
		return
	}
	sb.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
}

// appendEcmaString escapes a string per ECMA-262 JSON.stringify without HTML-escaping <, >, &.
func appendEcmaString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r >= 0 && r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}
