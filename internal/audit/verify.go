package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func Verify(eventsPath, rootsPath string, batchSize int) VerifyReport {
	report := VerifyReport{OK: true}
	file, err := os.OpenFile(eventsPath, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		report.OK = false
		report.Errors = append(report.Errors, fmt.Sprintf("open events: %v", err))
		return report
	}
	defer file.Close()

	roots, err := readRoots(rootsPath)
	if err != nil {
		report.OK = false
		report.Errors = append(report.Errors, fmt.Sprintf("read roots: %v", err))
		return report
	}
	rootIndex := 0
	var currentBatch []string
	var expectedPrev string
	var expectedIndex int64

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("decode record: %v", err))
			continue
		}
		expectedIndex++
		if rec.Index != expectedIndex {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("index mismatch at %d", rec.Index))
		}
		if rec.PrevHash != expectedPrev {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("prev_hash mismatch at %d", rec.Index))
		}
		payload, err := StableJSON(rec.Event)
		if err != nil {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("stable json: %v", err))
			continue
		}
		computed := hashBytes([]byte(rec.PrevHash), []byte(fmt.Sprintf("|%d|", rec.Index)), payload)
		if computed != rec.Hash {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("hash mismatch at %d", rec.Index))
		}
		expectedPrev = rec.Hash
		report.Total = rec.Index
		report.LastIndex = rec.Index
		report.LastHash = rec.Hash

		currentBatch = append(currentBatch, rec.Hash)
		if batchSize > 0 && len(currentBatch) == batchSize {
			if rootIndex >= len(roots) {
				report.OK = false
				report.Errors = append(report.Errors, "missing root record")
				currentBatch = nil
				continue
			}
			root := MerkleRoot(currentBatch)
			expected := roots[rootIndex]
			if expected.RootHash != root {
				report.OK = false
				report.Errors = append(report.Errors, fmt.Sprintf("root mismatch for batch ending %d", rec.Index))
			}
			report.RootsChecked++
			rootIndex++
			currentBatch = nil
		}
	}
	if err := scanner.Err(); err != nil {
		report.OK = false
		report.Errors = append(report.Errors, fmt.Sprintf("scan: %v", err))
	}

	return report
}

func readRoots(path string) ([]RootRecord, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
	out := []RootRecord{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec RootRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, scanner.Err()
}
