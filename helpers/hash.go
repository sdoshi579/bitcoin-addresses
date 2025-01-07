package helpers

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// Hash160 = ripemd160(sha256(data))
func GetHash160(data []byte) ([]byte, error) {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	_, err := ripemd160Hasher.Write(sha256Hash[:])
	if err != nil {
		return nil, err
	}
	return ripemd160Hasher.Sum(nil), nil
}

// Calculate checksum (double SHA-256)
func GetChecksum(data []byte) [32]byte {
	hash := sha256.Sum256(data)

	return sha256.Sum256(hash[:])
}

func TaggedHash(tag string, data []byte) []byte {
	// Step 1: Compute SHA256 of the tag
	tagHash := sha256.Sum256([]byte(tag))

	// Step 2: Prepare input for final hashing
	input := append(tagHash[:], tagHash[:]...) // Concatenate SHA256(tag) || SHA256(tag)
	input = append(input, data...)             // Append data

	// Step 3: Compute final hash
	finalHash := sha256.Sum256(input)

	return finalHash[:]
}
