package audit

import (
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"
)

func TestAuditChainDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 2)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, _, err := store.AppendEvent(Event{
			Type:      "trade",
			Source:    "test",
			Timestamp: time.Now().UTC(),
			Payload:   map[string]interface{}{"mint": "MINT", "seq": i},
		})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	eventsPath := filepath.Join(dir, "events.log")
	rootsPath := filepath.Join(dir, "roots.log")

	report := Verify(eventsPath, rootsPath, 2)
	if !report.OK {
		t.Fatalf("expected ok before tamper: %+v", report)
	}

	// Tamper with the log.
	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	data[10] = 'X'
	if err := os.WriteFile(eventsPath, data, 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	report = Verify(eventsPath, rootsPath, 2)
	if report.OK {
		t.Fatalf("expected tamper detection")
	}
}

func TestAuditChainProperty(t *testing.T) {
	f := func(n uint8) bool {
		dir := t.TempDir()
		store, err := NewStore(dir, 5)
		if err != nil {
			return false
		}
		count := int(n%20 + 1)
		for i := 0; i < count; i++ {
			_, _, err := store.AppendEvent(Event{
				Type:      "trade",
				Source:    "test",
				Timestamp: time.Now().UTC(),
				Payload:   map[string]interface{}{"seq": i},
			})
			if err != nil {
				return false
			}
		}
		report := Verify(filepath.Join(dir, "events.log"), filepath.Join(dir, "roots.log"), 5)
		return report.OK && report.Total == int64(count)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Fatalf("property check failed: %v", err)
	}
}
