package privacy

import "testing"

func TestSummarizeTokenCountsKAnon(t *testing.T) {
	counts := map[string]int{"A": 10, "B": 3, "C": 1}
	summary := SummarizeTokenCounts(counts, 5, 0.5, 1, 24)
	if summary.RedactedCount != 2 {
		t.Fatalf("expected 2 redacted, got %d", summary.RedactedCount)
	}
	if len(summary.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(summary.Items))
	}
	if summary.Items[0].Mint != "A" {
		t.Fatalf("expected A")
	}
}

func TestSummarizeTokenCountsNoise(t *testing.T) {
	counts := map[string]int{"A": 10}
	summary := SummarizeTokenCounts(counts, 1, 0.8, 42, 24)
	if len(summary.Items) != 1 {
		t.Fatalf("expected 1 item")
	}
	if summary.Items[0].Noised == float64(summary.Items[0].Count) {
		t.Fatalf("expected noise")
	}
}
