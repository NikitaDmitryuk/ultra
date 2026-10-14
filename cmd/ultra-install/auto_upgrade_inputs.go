package main

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// renderCanonicalInputs is shared by deployment configuration rewrites.
func renderCanonicalInputs(values map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output strings.Builder
	for _, key := range keys {
		value := values[key]
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(key) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("canonical_projection_value_invalid")
		}
		output.WriteString(key + "=" + strconv.Quote(value) + "\n")
	}
	return []byte(output.String()), nil
}
