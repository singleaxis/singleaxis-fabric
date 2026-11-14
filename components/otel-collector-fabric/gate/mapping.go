// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

// The fabricmap processor (spec 057 §4.5) rewrites telemetry from an emitter
// with its own attribute names into Fabric's neutral attribute families, by a
// customer-supplied mapping profile. It is optional and off unless a
// configuration names it. When it is present the gate holds it to these
// rules, so it can only narrow what reaches fabricguard and never stand in
// for it:
//
//   - one instance per Node, named exactly "fabricmap";
//   - in a traces or logs pipeline it runs once, directly before fabricguard
//     (never after the guard, never on a content pipeline);
//   - it stamps a tenant and source on the records it maps only when they
//     are the ones fabricguard binds the ingress to, and on a bound ingress
//     a profile always comes with that binding (fabricguard would otherwise
//     drop every mapped record for naming no source);
//   - it is not accepted on a Node with ingress groups.
//
// Diagnostics name component and pipeline ids only, never a path or an
// identity value.
func checkMapping(cfg map[string]any, groups bool) error {
	processors, _ := cfg["processors"].(map[string]any)
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	present := false
	for _, id := range sortedKeys(processors) {
		if componentType(id) != "fabricmap" {
			continue
		}
		present = true
		if id != "fabricmap" {
			return fmt.Errorf("processor %q: a Node runs one mapping processor; name it fabricmap (no /name suffix) and list every rule in its one mapping profile", id)
		}
	}
	for _, name := range sortedKeys(pipelines) {
		pipeline, _ := pipelines[name].(map[string]any)
		for _, step := range idList(pipeline["processors"]) {
			present = present || componentType(step) == "fabricmap"
		}
	}
	if !present {
		return nil
	}
	if groups {
		return fmt.Errorf("the fabricmap processor is not accepted on a Node with ingress groups (fabricguard/<group>); run the mapping profile on a Node with a single fabricguard, or remove fabricmap from this configuration")
	}
	mapper, isMap := processors["fabricmap"].(map[string]any)
	if processors["fabricmap"] != nil && !isMap {
		return fmt.Errorf("processor \"fabricmap\" is not a literal mapping; write it as a map with profile_file (individual fields may use ${env:...})")
	}
	used := false
	for _, name := range sortedKeys(pipelines) {
		pipeline, _ := pipelines[name].(map[string]any)
		steps := idList(pipeline["processors"])
		at, guard := -1, -1
		for i, step := range steps {
			switch componentType(step) {
			case "fabricmap":
				if at != -1 {
					return fmt.Errorf("pipeline %q runs fabricmap more than once; list it once, directly before fabricguard", name)
				}
				at = i
			case "fabricguard":
				if guard == -1 {
					guard = i
				}
			}
		}
		if at == -1 {
			continue
		}
		used = true
		if isContentPipeline(name) {
			return fmt.Errorf("content pipeline %q runs fabricmap; a mapping profile applies to telemetry only, so remove it from this pipeline", name)
		}
		if guard != at+1 {
			return fmt.Errorf("pipeline %q must run fabricmap directly before fabricguard (processors: [memory_limiter, fabricmap, fabricguard]); the guard closes every value the mapping writes", name)
		}
	}
	if !used {
		return nil
	}
	guardNode, _ := processors["fabricguard"].(map[string]any)
	bound, err := mappingBinding(guardNode["evidence_source_binding"])
	if err != nil {
		// checkDedicatedEvidenceIngress reports a malformed guard binding.
		bound = nil
	}
	stamped, err := mappingBinding(mapper["source_binding"])
	if err != nil {
		return fmt.Errorf("processor \"fabricmap\": source_binding needs tenant_id and source_id; copy both from fabricguard's evidence_source_binding")
	}
	profile, _ := mapper["profile_file"].(string)
	switch {
	case stamped != nil && guardNode["evidence_source_binding"] == nil:
		return fmt.Errorf("processor \"fabricmap\" sets source_binding but fabricguard has no evidence_source_binding; a mapped record may name a tenant and source only on an ingress bound to them, so remove source_binding or bind the ingress (fabricguard evidence_source_binding)")
	case stamped != nil && (bound == nil || *stamped != *bound):
		return fmt.Errorf("processor \"fabricmap\": source_binding differs from fabricguard's evidence_source_binding; set the same tenant_id and source_id on both")
	case stamped == nil && bound != nil && strings.TrimSpace(profile) != "":
		return fmt.Errorf("processor \"fabricmap\" has a profile_file but no source_binding, and fabricguard binds this ingress to one tenant and source: every mapped record would be dropped for naming neither; set processors.fabricmap.source_binding to fabricguard's evidence_source_binding (the same tenant_id and source_id)")
	}
	return nil
}

type mappingIdentity struct{ tenant, source string }

// mappingBinding resolves a tenant and source binding as the collector will
// (values may come from the environment); nil when the key is absent.
func mappingBinding(raw any) (*mappingIdentity, error) {
	if raw == nil {
		return nil, nil
	}
	node, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not a mapping")
	}
	tenant, _ := node["tenant_id"].(string)
	source, _ := node["source_id"].(string)
	id := mappingIdentity{tenant: expandEnvRefs(tenant), source: expandEnvRefs(source)}
	if !safeEvidenceIdentity(id.tenant) || !safeEvidenceIdentity(id.source) {
		return nil, fmt.Errorf("invalid identity")
	}
	return &id, nil
}
