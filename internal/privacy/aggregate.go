package privacy

import (
	"bufio"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"assurance_service/internal/audit"
)

type TokenCount struct {
	Mint      string  `json:"mint"`
	Count     int     `json:"count"`
	Noised    float64 `json:"noised"`
	WindowHrs int     `json:"window_hours"`
}

type TokenSummary struct {
	Items          []TokenCount `json:"items"`
	RedactedCount  int          `json:"redacted_count"`
	TotalSeen      int          `json:"total_seen"`
	AppliedK       int          `json:"k"`
	AppliedEpsilon float64      `json:"epsilon"`
}

func TokenCounts(eventsPath string, window time.Duration) (map[string]int, error) {
	counts := map[string]int{}
	cutoff := time.Now().Add(-window)

	file, err := os.OpenFile(eventsPath, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		if rec.Event.Type != "trade" {
			continue
		}
		if !rec.Event.Timestamp.IsZero() && rec.Event.Timestamp.Before(cutoff) {
			continue
		}
		mint := extractMint(rec.Event.Payload)
		if mint == "" {
			continue
		}
		counts[mint]++
	}
	return counts, scanner.Err()
}

func SummarizeTokenCounts(counts map[string]int, k int, epsilon float64, seed int64, windowHours int) TokenSummary {
	if k <= 0 {
		k = 1
	}
	if epsilon <= 0 {
		epsilon = 0.7
	}

	redacted := 0
	items := make([]TokenCount, 0, len(counts))
	var rng *rand.Rand
	if seed == 0 {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	} else {
		rng = rand.New(rand.NewSource(seed))
	}
	for mint, count := range counts {
		if count < k {
			redacted++
			continue
		}
		noise := laplace(rng, 1/epsilon)
		items = append(items, TokenCount{
			Mint:      mint,
			Count:     count,
			Noised:    float64(count) + noise,
			WindowHrs: windowHours,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Noised > items[j].Noised
	})

	total := 0
	for _, v := range counts {
		total += v
	}

	return TokenSummary{
		Items:          items,
		RedactedCount:  redacted,
		TotalSeen:      total,
		AppliedK:       k,
		AppliedEpsilon: epsilon,
	}
}

func extractMint(payload map[string]interface{}) string {
	if payload == nil {
		return ""
	}
	for _, key := range []string{"mint", "tokenMint", "token_address"} {
		if val, ok := payload[key]; ok {
			if s, ok := val.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func laplace(rng *rand.Rand, scale float64) float64 {
	if scale <= 0 {
		return 0
	}
	u := rng.Float64() - 0.5
	sign := 1.0
	if u < 0 {
		sign = -1.0
	}
	return -scale * sign * math.Log(1-2*math.Abs(u))
}
