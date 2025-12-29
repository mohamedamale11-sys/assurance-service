package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// StableJSON encodes v with deterministic key ordering for tamper-evident hashing.
func StableJSON(v interface{}) ([]byte, error) {
	stable, err := normalize(v)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(stable); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func normalize(v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]interface{}, 0, len(keys)*2)
		for _, k := range keys {
			nv, err := normalize(val[k])
			if err != nil {
				return nil, err
			}
			out = append(out, k, nv)
		}
		return out, nil
	case []interface{}:
		out := make([]interface{}, 0, len(val))
		for _, item := range val {
			nv, err := normalize(item)
			if err != nil {
				return nil, err
			}
			out = append(out, nv)
		}
		return out, nil
	case json.Number:
		return val.String(), nil
	case string, float64, bool, nil:
		return val, nil
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("normalize: %w", err)
		}
		var decoded interface{}
		if err := json.Unmarshal(b, &decoded); err != nil {
			return nil, fmt.Errorf("normalize: %w", err)
		}
		return normalize(decoded)
	}
}
