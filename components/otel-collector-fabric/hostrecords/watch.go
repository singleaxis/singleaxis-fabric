// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// WatchedPath is one entry of the capture policy's security_context
// watched_paths list (spec 057 §4.3): an exact path or a directory prefix,
// the customer's label and a class. A host sensor labels the opens it sees of
// a listed path in its own user space; the path itself never leaves the
// sensor (only the label, the class and the keyed pth- id of the entry's
// path). Fabric never opens, reads, stats or hashes a watched file.
type WatchedPath struct {
	Path  string `json:"path" mapstructure:"path"`
	Match string `json:"match" mapstructure:"match"`
	Label string `json:"label" mapstructure:"label"`
	Class string `json:"class" mapstructure:"class"`
}

// MaxWatchedPaths bounds the list, as every classification list (spec 057
// §4.4: at most 256 entries).
const MaxWatchedPaths = 256

var (
	// The deployment-policy schema's patterns (security_context.watched_paths).
	watchLabel   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	watchClasses = map[string]bool{
		"permission_config": true, "hook_config": true, "extension_dir": true,
		"credential_file": true, "other": true,
	}
)

// validWatchPath is the schema's `^/[ -~]{0,4095}$` (Go's regexp bounds a
// repeat at 1000): an absolute path of at most 4096 printable ASCII bytes.
func validWatchPath(p string) bool {
	if len(p) == 0 || len(p) > 4096 || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < ' ' || p[i] > '~' {
			return false
		}
	}
	return true
}

// WatchTable is a validated watched_paths list as frozen exact-match tables:
// one lookup for an exact entry, one per directory level for a prefix entry.
// Matching never normalises the path: it is the path the process passed to
// the kernel, so a relative path (resolved against a working directory or a
// directory descriptor) is never labelled.
type WatchTable struct {
	exact  map[string]*WatchedPath
	prefix map[string]*WatchedPath
}

// NewWatchTable validates entries and builds the table. An error names the
// entry by index and the rule it breaks, never its path or label, and says
// how to fix it.
func NewWatchTable(entries []WatchedPath) (*WatchTable, error) {
	if len(entries) > MaxWatchedPaths {
		return nil, fmt.Errorf("watched_paths has %d entries; at most %d are allowed: remove entries or watch a parent directory with match: prefix", len(entries), MaxWatchedPaths)
	}
	t := &WatchTable{exact: map[string]*WatchedPath{}, prefix: map[string]*WatchedPath{}}
	for i := range entries {
		e := entries[i]
		switch {
		case !validWatchPath(e.Path):
			return nil, fmt.Errorf("watched_paths[%d].path must be an absolute path of printable ASCII (at most 4096 characters)", i)
		case !watchLabel.MatchString(e.Label):
			return nil, fmt.Errorf("watched_paths[%d].label must match %s", i, watchLabel.String())
		case !watchClasses[e.Class]:
			return nil, fmt.Errorf("watched_paths[%d].class must be one of permission_config, hook_config, extension_dir, credential_file, other", i)
		}
		table := t.exact
		key := e.Path
		switch e.Match {
		case "exact":
		case "prefix":
			table = t.prefix
			if key != "/" {
				key = strings.TrimRight(key, "/")
			}
		default:
			return nil, fmt.Errorf("watched_paths[%d].match must be exact or prefix", i)
		}
		if _, dup := table[key]; dup {
			return nil, fmt.Errorf("watched_paths[%d] matches the same path as an earlier entry: remove one of the two", i)
		}
		table[key] = &e
	}
	return t, nil
}

// Len is the number of entries.
func (t *WatchTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.exact) + len(t.prefix)
}

// Match returns the entry an opened path falls under, or nil: an exact entry
// first, then the deepest prefix entry (a directory and everything below it).
// The lookups are exact (one map probe per directory level of the path).
func (t *WatchTable) Match(path string) *WatchedPath {
	if t == nil || len(path) == 0 || path[0] != '/' {
		return nil
	}
	if e, ok := t.exact[path]; ok {
		return e
	}
	if len(t.prefix) == 0 {
		return nil
	}
	for dir := strings.TrimRight(path, "/"); dir != ""; {
		if e, ok := t.prefix[dir]; ok {
			return e
		}
		i := strings.LastIndexByte(dir, '/')
		if i <= 0 {
			break
		}
		dir = dir[:i]
	}
	if e, ok := t.prefix["/"]; ok {
		return e
	}
	return nil
}

// ParseWatchedPaths reads a watched_paths list from JSON: either the list
// itself or a deployment policy (JSON form) whose security_context section
// holds it. Unknown entry fields are refused, as the policy schema does.
func ParseWatchedPaths(data []byte) ([]WatchedPath, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("watched paths file is empty: give a JSON list of {path, match, label, class} or a deployment policy in JSON")
	}
	list := trimmed
	if trimmed[0] == '{' {
		var policy struct {
			SecurityContext *struct {
				WatchedPaths json.RawMessage `json:"watched_paths"`
			} `json:"security_context"`
		}
		if err := json.Unmarshal(trimmed, &policy); err != nil {
			return nil, errors.New("watched paths file is not valid JSON")
		}
		if policy.SecurityContext == nil || len(policy.SecurityContext.WatchedPaths) == 0 {
			return nil, errors.New("watched paths file is a JSON object without security_context.watched_paths: add the list there, or give the list itself")
		}
		list = policy.SecurityContext.WatchedPaths
	}
	dec := json.NewDecoder(bytes.NewReader(list))
	dec.DisallowUnknownFields()
	var entries []WatchedPath
	if err := dec.Decode(&entries); err != nil {
		return nil, errors.New("watched_paths must be a JSON list of objects with exactly path, match, label and class")
	}
	return entries, nil
}
