package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu          sync.Mutex
	dataDir     string
	eventsPath  string
	rootsPath   string
	batchSize   int
	lastIndex   int64
	lastHash    string
	batchHashes []string
	batchStart  int64
}

func NewStore(dataDir string, batchSize int) (*Store, error) {
	if dataDir == "" {
		dataDir = "./data"
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	store := &Store{
		dataDir:    dataDir,
		eventsPath: filepath.Join(dataDir, "events.log"),
		rootsPath:  filepath.Join(dataDir, "roots.log"),
		batchSize:  batchSize,
	}
	if err := store.loadState(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) AppendEvent(event Event) (Record, *RootRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	index := s.lastIndex + 1
	payload, err := StableJSON(event)
	if err != nil {
		return Record{}, nil, err
	}
	rec := Record{
		Index:     index,
		Timestamp: time.Now().UTC(),
		Event:     event,
		PrevHash:  s.lastHash,
		Hash:      hashBytes([]byte(s.lastHash), []byte(fmt.Sprintf("|%d|", index)), payload),
	}

	if err := appendJSONLine(s.eventsPath, rec); err != nil {
		return Record{}, nil, err
	}

	s.lastIndex = rec.Index
	s.lastHash = rec.Hash

	if len(s.batchHashes) == 0 {
		s.batchStart = rec.Index
	}
	s.batchHashes = append(s.batchHashes, rec.Hash)

	var root *RootRecord
	if len(s.batchHashes) >= s.batchSize {
		r := RootRecord{
			FromIndex: s.batchStart,
			ToIndex:   rec.Index,
			RootHash:  MerkleRoot(s.batchHashes),
			CreatedAt: time.Now().UTC(),
		}
		if r.RootHash != "" {
			if err := appendJSONLine(s.rootsPath, r); err != nil {
				return rec, nil, err
			}
			root = &r
		}
		s.batchHashes = nil
		s.batchStart = 0
	}

	return rec, root, nil
}

func (s *Store) LastRoot() (*RootRecord, error) {
	return readLastRoot(s.rootsPath)
}

func (s *Store) CurrentBatchRoot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return MerkleRoot(s.batchHashes)
}

func (s *Store) loadState() error {
	lastRoot, err := readLastRoot(s.rootsPath)
	if err != nil {
		return err
	}
	lastCompletedIndex := int64(0)
	if lastRoot != nil {
		lastCompletedIndex = lastRoot.ToIndex
	}

	file, err := os.OpenFile(s.eventsPath, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("decode record: %w", err)
		}
		s.lastIndex = rec.Index
		s.lastHash = rec.Hash
		if rec.Index > lastCompletedIndex {
			if s.batchStart == 0 {
				s.batchStart = rec.Index
			}
			s.batchHashes = append(s.batchHashes, rec.Hash)
		}
	}
	return scanner.Err()
}

func appendJSONLine(path string, v interface{}) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func readLastRoot(path string) (*RootRecord, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var last *RootRecord
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec RootRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		last = &rec
	}
	return last, scanner.Err()
}
