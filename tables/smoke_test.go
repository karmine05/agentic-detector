package tables

import (
	"context"
	"os"
	"testing"
)

// TestSmokeLiveHost runs the unified table against the real host: first
// unconstrained (all kinds), then with a kind='ide_plugin' constraint to prove
// pushdown returns only that kind. Opt-in (AED_SMOKE=1) — reads live state.
//
//	AED_SMOKE=1 go test -run TestSmokeLiveHost -v ./tables/
func TestSmokeLiveHost(t *testing.T) {
	if os.Getenv("AED_SMOKE") != "1" {
		t.Skip("set AED_SMOKE=1 to run the live-host smoke test")
	}
	p := All()[0]
	ctx := context.Background()

	// 1. Unconstrained: every kind.
	resp := p.Call(ctx, map[string]string{"action": "generate", "context": "{}"})
	if resp.Status != nil && resp.Status.Code != 0 {
		t.Fatalf("generate failed: %s", resp.Status.Message)
	}
	counts := map[string]int{}
	for _, r := range resp.Response {
		counts[r["kind"]]++
	}
	t.Logf("agentic_software: %d rows total %v", len(resp.Response), counts)
	for i, r := range resp.Response {
		if i >= 4 {
			break
		}
		t.Logf("  [%d] kind=%s name=%q is_ai=%s category=%q location=%s", i, r["kind"], r["name"], r["is_ai"], r["category"], r["location"])
	}

	// 2. Constraint pushdown: kind = 'ide_plugin' (op 2 = EQUALS).
	pruned := p.Call(ctx, map[string]string{
		"action":  "generate",
		"context": `{"constraints":[{"name":"kind","affinity":"TEXT","list":[{"op":2,"expr":"ide_plugin"}]}]}`,
	})
	if pruned.Status != nil && pruned.Status.Code != 0 {
		t.Fatalf("constrained generate failed: %s", pruned.Status.Message)
	}
	for _, r := range pruned.Response {
		if r["kind"] != "ide_plugin" {
			t.Fatalf("pushdown leaked a non-ide_plugin row: kind=%s", r["kind"])
		}
	}
	t.Logf("kind='ide_plugin' pushdown: %d rows (all ide_plugin)", len(pruned.Response))
}
