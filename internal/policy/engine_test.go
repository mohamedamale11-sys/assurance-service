package policy

import "testing"

func TestPolicyDenyOverridesAllow(t *testing.T) {
	engine := &Engine{policy: Policy{Rules: []Rule{
		{ID: "allow", Effect: "allow", Actions: []string{"swap.execute"}, Resources: []string{"wallet"}, Roles: []string{"user"}},
		{ID: "deny-large", Effect: "deny", Actions: []string{"swap.execute"}, Resources: []string{"wallet"}, Roles: []string{"user"}, Conditions: []Condition{{Key: "context.amount_usd", Op: "gte", Value: 1000}}},
	}}}

	input := Input{
		Subject:  Subject{ID: "u1", Roles: []string{"user"}},
		Action:   "swap.execute",
		Resource: "wallet",
		Context:  map[string]interface{}{"amount_usd": 1500},
	}

	decision, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expected deny")
	}
	if len(decision.DeniedRules) == 0 {
		t.Fatalf("expected deny rule")
	}
}

func TestPolicyAllow(t *testing.T) {
	engine := &Engine{policy: Policy{Rules: []Rule{
		{ID: "allow", Effect: "allow", Actions: []string{"audit.ingest"}, Resources: []string{"trade"}, Roles: []string{"backend"}},
	}}}

	input := Input{
		Subject:  Subject{ID: "svc", Roles: []string{"backend"}},
		Action:   "audit.ingest",
		Resource: "trade",
	}

	decision, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	if !decision.Allow {
		t.Fatalf("expected allow")
	}
}
