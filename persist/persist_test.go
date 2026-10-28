// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
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

package persist_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

func TestPersist(t *testing.T) {
	// No tests yet
}

func testRuleCount(t *testing.T, model model.Model, expected int, sec string, ptype string, tag string) {
	t.Helper()

	ruleCount := len(model[sec][ptype].Policy)
	if ruleCount != expected {
		t.Errorf("[%s] rule count: %d, expected %d", tag, ruleCount, expected)
	}
}

func TestDuplicateRuleInAdapter(t *testing.T) {
	e, _ := casbin.NewEnforcer("../examples/basic_model.conf")

	_, _ = e.AddPolicy("alice", "data1", "read")
	_, _ = e.AddPolicy("alice", "data1", "read")

	testRuleCount(t, e.GetModel(), 1, "p", "p", "AddPolicy")

	e.ClearPolicy()

	// simulate adapter.LoadPolicy with duplicate rules
	_ = persist.LoadPolicyArray([]string{"p", "alice", "data1", "read"}, e.GetModel())
	_ = persist.LoadPolicyArray([]string{"p", "alice", "data1", "read"}, e.GetModel())

	testRuleCount(t, e.GetModel(), 1, "p", "p", "LoadPolicyArray")
}

func TestPolicyLineToCsv(t *testing.T) {
	tests := []struct {
		name     string
		ptype    string
		rule     []string
		expected string
	}{
		{
			// Fields are separated by ", ", the layout used by the policy files
			// under examples/, so that SavePolicy does not reformat them.
			name:     "plain fields keep the space after the comma",
			ptype:    "p",
			rule:     []string{"alice", "data1", "read"},
			expected: "p, alice, data1, read",
		},
		{
			name:     "field containing a comma is quoted",
			ptype:    "p",
			rule:     []string{"alice", "data1", "read", "r.attrs in ('val1','val2')"},
			expected: `p, alice, data1, read, "r.attrs in ('val1','val2')"`,
		},
		{
			name:     "field containing a quote is escaped",
			ptype:    "p",
			rule:     []string{"alice", `say "hi"`, "read"},
			expected: `p, alice, "say ""hi""", read`,
		},
		{
			// A leading space must stay quoted: LoadPolicyLine trims leading
			// spaces on unquoted fields.
			name:     "field with a leading space is quoted",
			ptype:    "g",
			rule:     []string{" alice", "admin"},
			expected: `g, " alice", admin`,
		},
		{
			name:     "empty field",
			ptype:    "p",
			rule:     []string{"alice", "", "read"},
			expected: "p, alice, , read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, err := persist.PolicyLineToCsv(tt.ptype, tt.rule)
			if err != nil {
				t.Fatalf("PolicyLineToCsv: %v", err)
			}
			if line != tt.expected {
				t.Errorf("line: %q, expected %q", line, tt.expected)
			}
		})
	}
}

func TestPolicyLineToCsvRoundTrip(t *testing.T) {
	conf := `
[request_definition]
r = sub, obj, act, cond

[policy_definition]
p = sub, obj, act, cond

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	rule := []string{" alice", `say "hi"`, "read", "r.attrs in ('val1','val2')"}

	line, err := persist.PolicyLineToCsv("p", rule)
	if err != nil {
		t.Fatalf("PolicyLineToCsv: %v", err)
	}

	m := model.NewModel()
	if err = m.LoadModelFromText(conf); err != nil {
		t.Fatalf("load model: %v", err)
	}
	if err = persist.LoadPolicyLine(line, m); err != nil {
		t.Fatalf("LoadPolicyLine on %q: %v", line, err)
	}

	rules, err := m.GetPolicy("p", "p")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count: %d, expected 1 (line: %q)", len(rules), line)
	}
	if !reflect.DeepEqual(rules[0], rule) {
		t.Errorf("rule after round-trip: %q, expected %q (line: %q)", rules[0], rule, line)
	}
}

// A policy file keeps one rule per line and the adapters hand LoadPolicyLine one
// physical line at a time, so a field containing a line break has no encoding
// that can be read back. PolicyLineToCsv must say so instead of returning a
// "line" that spans several physical lines.
func TestPolicyLineToCsvLineBreaks(t *testing.T) {
	tests := []struct {
		name    string
		ptype   string
		rule    []string
		wantErr bool
	}{
		{
			name:    "field containing a line break",
			ptype:   "p",
			rule:    []string{"alice", "first\nsecond", "read"},
			wantErr: true,
		},
		{
			name:    "field containing a carriage return and a line break",
			ptype:   "p",
			rule:    []string{"alice", "first\r\nsecond", "read"},
			wantErr: true,
		},
		{
			// A lone carriage return leaves the rule on one physical line, so
			// LoadPolicyLine can still read it back.
			name:  "field containing a lone carriage return",
			ptype: "p",
			rule:  []string{"alice", "first\rsecond", "read"},
		},
		{
			name:  "fields that need quoting still work",
			ptype: "p",
			rule:  []string{"alice", "data1", "read", "r.attrs in ('val1','val2')"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, err := persist.PolicyLineToCsv(tt.ptype, tt.rule)
			if tt.wantErr {
				if err != nil {
					return
				}
				if strings.Contains(line, "\n") {
					t.Fatalf("PolicyLineToCsv returned the multi-line %q for rule %q, "+
						"a policy file cannot store it", line, tt.rule)
				}
				return
			}
			if err != nil {
				t.Fatalf("PolicyLineToCsv: %v", err)
			}
			if strings.Contains(line, "\n") {
				t.Errorf("line: %q, expected a single physical line", line)
			}
		})
	}
}

// The corruption is only visible in the saved file: an unreadable policy file is
// written and the rules behind it are lost on the next start.
func TestSavePolicyWithLineBreakRule(t *testing.T) {
	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	dir := t.TempDir()
	confPath := filepath.Join(dir, "model.conf")
	policyPath := filepath.Join(dir, "policy.csv")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write model: %v", err)
	}
	original := "p, alice, data1, read\n"
	if err := os.WriteFile(policyPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	e, err := casbin.NewEnforcer(confPath, policyPath)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	rule := []string{"bob", "first\nsecond", "write"}
	if _, err = e.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	saveErr := e.SavePolicy()
	saved, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if saveErr != nil {
		if string(saved) != original {
			t.Errorf("policy file after the failed save: %q, expected it untouched at %q", saved, original)
		}
		_, err = casbin.NewEnforcer(confPath, policyPath)
		if err != nil {
			t.Errorf("the untouched policy file must still load: %v", err)
		}
		return
	}

	reloaded, err := casbin.NewEnforcer(confPath, policyPath)
	if err != nil {
		t.Fatalf("SavePolicy wrote %q, which cannot be loaded back: %v", saved, err)
	}
	got, err := reloaded.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	for _, want := range [][]string{{"alice", "data1", "read"}, rule} {
		found := false
		for _, g := range got {
			if reflect.DeepEqual(g, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %q is gone after save and reload, got %q (file: %q)", want, got, saved)
		}
	}
}
