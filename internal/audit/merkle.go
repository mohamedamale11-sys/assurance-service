package audit

import (
	"crypto/sha256"
	"encoding/hex"
)

// MerkleRoot computes a binary Merkle root from a slice of hex hashes.
func MerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	level := make([][]byte, 0, len(hashes))
	for _, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return ""
		}
		level = append(level, b)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			var right []byte
			if i+1 < len(level) {
				right = level[i+1]
			} else {
				right = left
			}
			next = append(next, hashPair(left, right))
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
