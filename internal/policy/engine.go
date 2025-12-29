package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Policy struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	ID         string      `json:"id"`
	Effect     string      `json:"effect"`
	Actions    []string    `json:"actions"`
	Resources  []string    `json:"resources"`
	Roles      []string    `json:"roles"`
	Conditions []Condition `json:"conditions"`
}

type Condition struct {
	Key   string      `json:"key"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

type Subject struct {
	ID         string                 `json:"id"`
	Roles      []string               `json:"roles"`
	Attributes map[string]interface{} `json:"attributes"`
}

type Input struct {
	Subject  Subject                `json:"subject"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Context  map[string]interface{} `json:"context"`
}

type Decision struct {
	Allow         bool     `json:"allow"`
	MatchedRules  []string `json:"matched_rules"`
	DeniedRules   []string `json:"denied_rules"`
	Reason        string   `json:"reason"`
	DefaultDeny   bool     `json:"default_deny"`
	EvaluatedRule int      `json:"evaluated_rules"`
}

type Engine struct {
	policy Policy
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &Engine{policy: pol}, nil
}

func (e *Engine) Evaluate(input Input) (Decision, error) {
	if e == nil {
		return Decision{}, errors.New("policy engine not configured")
	}
	decision := Decision{DefaultDeny: true}
	allowFound := false

	for _, rule := range e.policy.Rules {
		decision.EvaluatedRule++
		if !matchString(rule.Actions, input.Action) {
			continue
		}
		if !matchString(rule.Resources, input.Resource) {
			continue
		}
		if len(rule.Roles) > 0 && !intersects(rule.Roles, input.Subject.Roles) {
			continue
		}
		if !conditionsMatch(rule.Conditions, input) {
			continue
		}

		effect := strings.ToLower(strings.TrimSpace(rule.Effect))
		switch effect {
		case "deny":
			decision.DeniedRules = append(decision.DeniedRules, rule.ID)
		case "allow":
			allowFound = true
			decision.MatchedRules = append(decision.MatchedRules, rule.ID)
		default:
			return Decision{}, fmt.Errorf("unknown policy effect: %s", rule.Effect)
		}
	}

	if len(decision.DeniedRules) > 0 {
		decision.Allow = false
		decision.Reason = "explicit deny"
		return decision, nil
	}
	if allowFound {
		decision.Allow = true
		decision.Reason = "allow"
		decision.DefaultDeny = false
		return decision, nil
	}

	decision.Allow = false
	decision.Reason = "no matching allow"
	return decision, nil
}

func matchString(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if strings.EqualFold(p, value) {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	set := map[string]struct{}{}
	for _, v := range a {
		set[strings.ToLower(v)] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[strings.ToLower(v)]; ok {
			return true
		}
	}
	return false
}

func conditionsMatch(conds []Condition, input Input) bool {
	for _, cond := range conds {
		if cond.Key == "" {
			continue
		}
		actual, ok := resolveValue(cond.Key, input)
		if !ok {
			return false
		}
		if !compare(actual, cond.Op, cond.Value) {
			return false
		}
	}
	return true
}

func resolveValue(path string, input Input) (interface{}, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil, false
	}
	var current interface{}
	switch parts[0] {
	case "subject":
		current = input.Subject.Attributes
	case "context":
		current = input.Context
	default:
		return nil, false
	}

	for _, part := range parts[1:] {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func compare(actual interface{}, op string, expected interface{}) bool {
	switch strings.ToLower(op) {
	case "eq":
		return toString(actual) == toString(expected)
	case "neq":
		return toString(actual) != toString(expected)
	case "gte":
		av, okA := toFloat(actual)
		ev, okE := toFloat(expected)
		return okA && okE && av >= ev
	case "lte":
		av, okA := toFloat(actual)
		ev, okE := toFloat(expected)
		return okA && okE && av <= ev
	case "in":
		expectedList, ok := expected.([]interface{})
		if !ok {
			return false
		}
		for _, item := range expectedList {
			if toString(item) == toString(actual) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toFloat(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		f, err := json.Number(val).Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
