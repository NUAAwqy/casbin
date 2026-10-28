// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package model

import (
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/util"
)

// policySepKey is how Policy keys PolicyMap: the rule fields joined with DefaultSep.
func policySepKey(rule []string) string {
	return strings.Join(rule, DefaultSep)
}

// newPolicyModel returns a model of the basic access-control shape, holding the
// given rules in the "p"/"p" assertion.
func newPolicyModel(t *testing.T, rules [][]string) Model {
	t.Helper()

	m := NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	for _, rule := range rules {
		if err := m.AddPolicy("p", "p", rule); err != nil {
			t.Fatalf("AddPolicy(%q): %v", rule, err)
		}
	}
	return m
}

// assertPolicyMapMatchesSlice checks the invariant that PolicyMap is exactly an
// index of Policy: one entry per row, each pointing at the row it names. When it
// breaks, a rule stays visible in GetPolicy but HasPolicy, RemovePolicy and
// UpdatePolicy can no longer find it.
func assertPolicyMapMatchesSlice(t *testing.T, m Model) {
	t.Helper()

	assertion := m["p"]["p"]
	if len(assertion.PolicyMap) != len(assertion.Policy) {
		t.Errorf("PolicyMap has %d entries but Policy has %d rows: %q",
			len(assertion.PolicyMap), len(assertion.Policy), assertion.Policy)
	}

	for i, rule := range assertion.Policy {
		key := policySepKey(rule)
		index, ok := assertion.PolicyMap[key]
		if !ok {
			t.Errorf("PolicyMap has no entry for row %d %q, so HasPolicy/RemovePolicy cannot find it", i, rule)
			continue
		}
		if index != i {
			t.Errorf("PolicyMap[%q] = %d, want %d (the row is at index %d)", key, index, i, i)
		}
	}

	for key, index := range assertion.PolicyMap {
		if index < 0 || index >= len(assertion.Policy) {
			t.Errorf("PolicyMap[%q] = %d, out of range for %d rows", key, index, len(assertion.Policy))
			continue
		}
		if got := assertion.Policy[index]; policySepKey(got) != key {
			t.Errorf("PolicyMap has a phantom key %q pointing at row %d %q", key, index, got)
		}
	}

	// The same invariant seen through the public API: every rule the model
	// reports has to be one the model can find.
	policy, err := m.GetPolicy("p", "p")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	for _, rule := range policy {
		ok, err := m.HasPolicy("p", "p", rule)
		if err != nil {
			t.Fatalf("HasPolicy(%q): %v", rule, err)
		}
		if !ok {
			t.Errorf("GetPolicy reports %q but HasPolicy says the model does not have it", rule)
		}
	}
}

func TestUpdatePoliciesKeepsPolicyMap(t *testing.T) {
	tests := []struct {
		name        string
		policy      [][]string
		oldRules    [][]string
		newRules    [][]string
		wantUpdated bool
		wantPolicy  [][]string
	}{
		{
			name:   "batch that swaps two rules",
			policy: [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
			oldRules: [][]string{
				{"alice", "data1", "read"},
				{"bob", "data2", "write"},
			},
			newRules: [][]string{
				{"bob", "data2", "write"},
				{"alice", "data1", "read"},
			},
			wantUpdated: true,
			// oldRules[i] is replaced by newRules[i] at the same position.
			wantPolicy: [][]string{{"bob", "data2", "write"}, {"alice", "data1", "read"}},
		},
		{
			name:   "batch that rotates three rules",
			policy: [][]string{{"a", "d1", "read"}, {"b", "d2", "read"}, {"c", "d3", "read"}},
			oldRules: [][]string{
				{"a", "d1", "read"},
				{"b", "d2", "read"},
				{"c", "d3", "read"},
			},
			newRules: [][]string{
				{"b", "d2", "read"},
				{"c", "d3", "read"},
				{"a", "d1", "read"},
			},
			wantUpdated: true,
			wantPolicy:  [][]string{{"b", "d2", "read"}, {"c", "d3", "read"}, {"a", "d1", "read"}},
		},
		{
			name:   "batch of unrelated new rules",
			policy: [][]string{{"katy", "data4", "write"}, {"leyo", "data4", "read"}},
			oldRules: [][]string{
				{"katy", "data4", "write"},
				{"leyo", "data4", "read"},
			},
			newRules: [][]string{
				{"katy", "data1", "write"},
				{"leyo", "data4", "write"},
			},
			wantUpdated: true,
			wantPolicy:  [][]string{{"katy", "data1", "write"}, {"leyo", "data4", "write"}},
		},
		{
			name:   "unknown old rule leaves the model untouched",
			policy: [][]string{{"alice", "data1", "read"}},
			oldRules: [][]string{
				{"alice", "data1", "read"},
				{"ghost", "data9", "read"},
			},
			newRules: [][]string{
				{"alice", "data1", "write"},
				{"ghost", "data9", "write"},
			},
			wantUpdated: false,
			wantPolicy:  [][]string{{"alice", "data1", "read"}},
		},
		{
			name:        "same old rule twice leaves the model untouched",
			policy:      [][]string{{"alice", "data1", "read"}},
			oldRules:    [][]string{{"alice", "data1", "read"}, {"alice", "data1", "read"}},
			newRules:    [][]string{{"alice", "data1", "write"}, {"alice", "data1", "deny"}},
			wantUpdated: false,
			wantPolicy:  [][]string{{"alice", "data1", "read"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newPolicyModel(t, tt.policy)

			updated, err := m.UpdatePolicies("p", "p", tt.oldRules, tt.newRules)
			if err != nil {
				t.Fatalf("UpdatePolicies: %v", err)
			}
			if updated != tt.wantUpdated {
				t.Errorf("UpdatePolicies returned %v, want %v", updated, tt.wantUpdated)
			}

			got, err := m.GetPolicy("p", "p")
			if err != nil {
				t.Fatalf("GetPolicy: %v", err)
			}
			if !util.Array2DEquals(got, tt.wantPolicy) {
				t.Errorf("policy after UpdatePolicies: %q, want %q", got, tt.wantPolicy)
			}

			assertPolicyMapMatchesSlice(t, m)
		})
	}
}
