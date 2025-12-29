package server

import (
	"bufio"
	"encoding/json"
	"os"

	"assurance_service/internal/audit"
)

func readLastEvents(path string, limit int) ([]audit.Record, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	items := make([]audit.Record, 0, limit)
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
		items = append(items, rec)
		if len(items) > limit {
			items = items[len(items)-limit:]
		}
	}
	return items, scanner.Err()
}
