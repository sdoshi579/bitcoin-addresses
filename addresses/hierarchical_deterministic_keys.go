package addresses

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	eciesgo "github.com/ecies/go/v2"
	"github.com/sdoshi579/bitcoin-addresses/helpers"
	"golang.org/x/crypto/pbkdf2"
)

func GetEntropy(allowedBits int) ([]byte, error) {
	if !allowedBitsIsValid(allowedBits) {
		return nil, errors.New("seedBits is not valid")
	}

	entropy := make([]byte, allowedBits/8)
	_, err := rand.Read(entropy[:])
	if err != nil {
		return nil, err
	}
	return entropy, nil
}

func allowedBitsIsValid(allowedBits int) bool {
	if allowedBits < 128 || allowedBits > 256 {
		return false
	}

	for i := 128; i <= 256; i += 32 {
		if i == allowedBits {
			return true
		}
	}

	return false
}

func GetRecoveryCodesFromEntropy(entropy []byte) []string {
	checksum := sha256.Sum256(entropy)
	checksumBitsRequired := (len(entropy) * 8) / 32

	recoveryCodesBits := helpers.ByteToBitsInt(entropy)
	checksumBit := helpers.ByteToBitsInt(checksum[:])

	recoveryCodesBits = append(recoveryCodesBits, checksumBit[:checksumBitsRequired]...)
	recoveryCodes := []string{}

	for i := 0; i < len(recoveryCodesBits); i += 11 {
		recoveryCodes = append(recoveryCodes, helpers.Words[helpers.BinaryUintToInt(recoveryCodesBits[i:i+11])])
	}
	return recoveryCodes
}

func GetSeedFromRecoveryCodes(recoveryCodes []string, salt string) []byte {
	password := strings.Join(recoveryCodes, " ")
	salt = "mnemonic" + salt
	iterations := 2048
	seedLength := 64
	hashFunction := sha512.New
	return pbkdf2.Key([]byte(password), []byte(salt), iterations, seedLength, hashFunction)
}

func GetMasterPrivateKeyAndMasterChainCodeFromSeed(seed []byte) ([]byte, []byte) {
	// Key is fixed for given cryptocurrency
	// Btc - Bitcoin seed
	// Eth - Ethereum seed
	// Sol - ed25519 seed
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))

	// Write the message to the hasher
	h.Write(seed)

	// Get the resulting HMAC-SHA512 digest (a []byte)
	hash := h.Sum(nil)
	// privateKeyAndChainCode := hash.Write(seed)
	return hash[:32], hash[32:]
}

const (
	secp256k1OrderHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
)

// KeyDerivationRequest represents the input for key derivation.
type KeyDerivationRequest struct {
	MasterPrivateKey []byte // The parent private key (32 bytes)
	MasterChainCode  []byte // The parent chain code (32 bytes)
	Path             string // The derivation path (e.g., "m/0/0/0'")
}

// KeyDerivationResponse represents the output of key derivation.
type KeyDerivationResponse struct {
	PrivateKey []byte // The derived private key (32 bytes)
	PublicKey  []byte // The derived public key (compressed, 33 bytes)
	ChainCode  []byte // The derived chain code (32 bytes)
	Path       string // The derivation path used to derive the keys
}

// GetChildHardenedKey generates a child hardened private key and chain code from a master private key and chain code.
// It follows the BIP-32 standard for hierarchical deterministic wallets.
//
// Parameters:
// - masterPrivateKey: The parent private key (32 bytes).
// - masterChainCode: The parent chain code (32 bytes).
// - path: The derivation path (e.g., "m/0'/1'/2'").
//
// Returns:
// - childPrivateKey: The derived child private key (32 bytes).
// - childChainCode: The derived child chain code (32 bytes).
// - error: An error if the derivation fails.
func GetChildHardenedKey(masterPrivateKey, masterChainCode []byte, path string) ([]byte, []byte, error) {
	// Validate the derivation path
	if err := validateNormalPath(path); err != nil {
		return nil, nil, err
	}

	// Get the last hardened index from the derivation path
	lastIndex, err := getLastHardenedIndexFromPath(path)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the index as a 4-byte big-endian value
	serializedIndex, err := serializeIndex(lastIndex)
	if err != nil {
		return nil, nil, err
	}

	// Prepare the data for HMAC-SHA512: 0x00 || masterPrivateKey || serializedIndex
	dataBuffer := new(bytes.Buffer)
	dataBuffer.WriteByte(0x00) // Padding byte for private key derivation
	dataBuffer.Write(masterPrivateKey)
	dataBuffer.Write(serializedIndex)
	concatenatedData := dataBuffer.Bytes()

	// Compute HMAC-SHA512 using the master chain code as the key
	il, ir, err := computeHMAC(masterChainCode, concatenatedData)
	if err != nil {
		return nil, nil, err
	}

	// Compute the child private key: (IL + masterPrivateKey) mod secp256k1Order
	childPrivateKey, err := computeChildPrivateKey(il, masterPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// Return the child private key and chain code
	return childPrivateKey, ir, nil
}

// GetChildNormalKey generates a child normal private key and chain code from a master private key, public key, and chain code.
// It follows the BIP-32 standard for hierarchical deterministic wallets.
//
// Parameters:
// - masterPrivateKey: The parent private key (32 bytes).
// - masterPublicKey: The parent public key (compressed, 33 bytes).
// - masterChainCode: The parent chain code (32 bytes).
// - path: The derivation path (e.g., "m/0/1").
//
// Returns:
// - childPrivateKey: The derived child private key (32 bytes).
// - childChainCode: The derived child chain code (32 bytes).
// - error: An error if the derivation fails.
func GetChildNormalKey(masterPrivateKey, masterPublicKey, masterChainCode []byte, path string) ([]byte, []byte, error) {
	// Validate the derivation path
	if err := validateNormalPath(path); err != nil {
		return nil, nil, err
	}

	// Get the last index from the derivation path
	lastIndex, err := getLastIndexFromPath(path)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the index as a 4-byte big-endian value
	serializedIndex, err := serializeIndex(lastIndex)
	if err != nil {
		return nil, nil, err
	}

	// Concatenate the serialized parent public key and the serialized index
	concatenatedData := concatenateData(masterPublicKey, serializedIndex)

	// Compute HMAC-SHA512 using the master chain code as the key
	il, ir, err := computeHMAC(masterChainCode, concatenatedData)
	if err != nil {
		return nil, nil, err
	}

	// Compute the child private key: (IL + masterPrivateKey) mod secp256k1Order
	childPrivateKey, err := computeChildPrivateKey(il, masterPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// Return the child private key and chain code
	return childPrivateKey, ir, nil
}

// GetNormalPublicKey generates a child normal public key and chain code from a master public key and chain code.
// It follows the BIP-32 standard for hierarchical deterministic wallets.
//
// Parameters:
// - masterPublicKey: The parent public key (compressed, 33 bytes).
// - masterChainCode: The parent chain code (32 bytes).
// - path: The derivation path (e.g., "m/0/1").
//
// Returns:
// - childPublicKey: The derived child public key (compressed, 33 bytes).
// - childChainCode: The derived child chain code (32 bytes).
// - error: An error if the derivation fails.
func GetNormalPublicKey(masterPublicKey, masterChainCode []byte, path string) ([]byte, []byte, error) {
	// Validate the derivation path
	if err := validateNormalPath(path); err != nil {
		return nil, nil, err
	}

	// Get the last index from the derivation path
	lastIndex, err := getLastIndexFromPath(path)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the index as a 4-byte big-endian value
	serializedIndex, err := serializeIndex(lastIndex)
	if err != nil {
		return nil, nil, err
	}

	// Concatenate the serialized parent public key and the serialized index
	concatenatedData := concatenateData(masterPublicKey, serializedIndex)

	// Compute HMAC-SHA512 using the master chain code as the key
	il, ir, err := computeHMAC(masterChainCode, concatenatedData)
	if err != nil {
		return nil, nil, err
	}

	// Compute the child public key
	childPublicKey, err := computeChildPublicKey(masterPublicKey, il)
	if err != nil {
		return nil, nil, err
	}

	// Return the child public key and chain code
	return childPublicKey, ir, nil
}

// GetChildKeyFromPath derives a child key (private key, public key, and chain code) from a master private key and chain code
// based on a full derivation path (e.g., "m/0/0/0'").
//
// Parameters:
// - req: A KeyDerivationRequest containing the master private key, chain code, and derivation path.
//
// Returns:
// - A KeyDerivationResponse containing the derived private key, public key, chain code, and path.
// - An error if the derivation fails.
func GetChildKeyFromPath(req KeyDerivationRequest) (KeyDerivationResponse, error) {
	// Validate the derivation path
	if err := validateNormalPath(req.Path); err != nil {
		return KeyDerivationResponse{}, err
	}

	// Split the path into components (e.g., "m/0/0/0'" -> ["m", "0", "0", "0'"])
	pathComponents := strings.Split(req.Path, "/")

	// Start with the master private key and chain code
	currentPrivateKey := req.MasterPrivateKey
	currentChainCode := req.MasterChainCode
	currentPublicKey := helpers.GetPublicKey(currentPrivateKey) // Derive the public key from the private key

	// Process each component of the path (skip the first component "m")
	for i := 1; i < len(pathComponents); i++ {
		component := pathComponents[i]

		// Check if the component is hardened (ends with "'")
		if strings.HasSuffix(component, "'") {
			fmt.Printf("Deriving hardened key for component: %s,\n private key: %x,\n chain code: %x\n", component, currentPrivateKey, currentChainCode)
			// Hardened key derivation
			_, err := getLastHardenedIndexFromPath("m/" + component)
			if err != nil {
				return KeyDerivationResponse{}, err
			}
			currentPrivateKey, currentChainCode, err = GetChildHardenedKey(currentPrivateKey, currentChainCode, "m/"+component)
			if err != nil {
				return KeyDerivationResponse{}, err
			}
			// Update the public key after hardened derivation
			currentPublicKey = helpers.GetPublicKey(currentPrivateKey)
		} else {
			fmt.Printf("Deriving normal key for component: %s,\n private key: %x,\n chain code: %x\n", component, currentPrivateKey, currentChainCode)
			// Normal key derivation
			index, err := strconv.Atoi(component)
			if err != nil {
				return KeyDerivationResponse{}, fmt.Errorf("invalid index in path: %s", component)
			}
			serializedIndex, err := serializeIndex(index)
			if err != nil {
				return KeyDerivationResponse{}, err
			}
			concatenatedData := concatenateData(currentPublicKey, serializedIndex)
			il, ir, err := computeHMAC(currentChainCode, concatenatedData)
			if err != nil {
				return KeyDerivationResponse{}, err
			}
			currentPrivateKey, err = computeChildPrivateKey(il, currentPrivateKey)
			if err != nil {
				return KeyDerivationResponse{}, err
			}
			currentChainCode = ir
			// Update the public key after normal derivation
			currentPublicKey = helpers.GetPublicKey(currentPrivateKey)
		}
	}

	// Return the final derived private key, public key, chain code, and path
	return KeyDerivationResponse{
		PrivateKey: currentPrivateKey,
		PublicKey:  currentPublicKey,
		ChainCode:  currentChainCode,
		Path:       req.Path,
	}, nil
}

//
// Helper Functions
//

// validateNormalPath validates the derivation path for normal keys.
func validateNormalPath(path string) error {
	if !strings.HasPrefix(path, "m/") {
		return errors.New("invalid derivation path: must start with 'm/'")
	}
	return nil
}

// getLastIndexFromPath extracts the last index from the derivation path.
func getLastIndexFromPath(path string) (int, error) {
	pathComponents := strings.Split(path, "/")
	lastIndex, err := strconv.Atoi(pathComponents[len(pathComponents)-1])
	if err != nil || lastIndex < 0 || lastIndex > int(math.Pow(2, 31)-1) {
		return 0, errors.New("invalid normal key index: must be between 0 and 2^31-1")
	}
	return lastIndex, nil
}

// getLastHardenedIndexFromPath extracts and validates the last index from the derivation path for hardened keys.
// Hardened keys require the index to end with a "'" (e.g., "0'").
//
// Parameters:
// - path: The derivation path (e.g., "m/0'/1'/2'").
//
// Returns:
// - lastIndex: The last index as an integer (e.g., 2147483648 for "0'").
// - error: An error if the index is invalid.
func getLastHardenedIndexFromPath(path string) (int, error) {
	pathComponents := strings.Split(path, "/")
	lastComponent := pathComponents[len(pathComponents)-1]

	// Ensure the last component ends with a "'" (indicating a hardened key)
	if !strings.HasSuffix(lastComponent, "'") {
		return 0, errors.New("invalid hardened key index: must end with a \"'\"")
	}

	// Remove the "'" and parse the index as an integer
	indexStr := strings.TrimSuffix(lastComponent, "'")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 {
		return 0, errors.New("invalid hardened key index: must be a non-negative integer")
	}

	// Add 2^31 to the index to indicate it's a hardened key
	return index + int(math.Pow(2, 31)), nil
}

// serializeIndex serializes the index as a 4-byte big-endian value.
func serializeIndex(index int) ([]byte, error) {
	indexBuffer := new(bytes.Buffer)
	if err := binary.Write(indexBuffer, binary.BigEndian, uint32(index)); err != nil {
		return nil, fmt.Errorf("failed to serialize index: %w", err)
	}
	return indexBuffer.Bytes(), nil
}

// concatenateData concatenates the parent public key and the serialized index.
func concatenateData(publicKey, serializedIndex []byte) []byte {
	data := new(bytes.Buffer)
	data.Write(publicKey)
	data.Write(serializedIndex)
	return data.Bytes()
}

// computeHMAC computes the HMAC-SHA512 of the given data using the provided key.
func computeHMAC(key, data []byte) ([]byte, []byte, error) {
	hmacHasher := hmac.New(sha512.New, key)
	hmacHasher.Write(data)
	hmacResult := hmacHasher.Sum(nil)
	return hmacResult[:32], hmacResult[32:], nil
}

// computeChildPrivateKey computes the child private key using the IL value and the parent private key.
func computeChildPrivateKey(il, masterPrivateKey []byte) ([]byte, error) {
	ilInt := new(big.Int).SetBytes(il)
	masterPrivateKeyInt := new(big.Int).SetBytes(masterPrivateKey)

	secp256k1Order := new(big.Int)
	if _, ok := secp256k1Order.SetString(secp256k1OrderHex, 16); !ok {
		return nil, errors.New("failed to parse secp256k1 order")
	}

	childPrivateKeyInt := new(big.Int).Add(ilInt, masterPrivateKeyInt)
	childPrivateKeyInt.Mod(childPrivateKeyInt, secp256k1Order)

	return childPrivateKeyInt.Bytes(), nil
}

// computeChildPublicKey computes the child public key using the IL value and the parent public key.
func computeChildPublicKey(masterPublicKey, il []byte) ([]byte, error) {
	parentEcdsa, err := eciesgo.NewPublicKeyFromBytes(masterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse master public key: %w", err)
	}

	ilInt := new(big.Int).SetBytes(il)
	pointX, pointY := parentEcdsa.ScalarBaseMult(ilInt.Bytes())
	pointHMAC := &ecdsa.PublicKey{Curve: parentEcdsa.Curve, X: pointX, Y: pointY}

	childPointX, childPointY := parentEcdsa.Add(pointHMAC.X, pointHMAC.Y, parentEcdsa.X, parentEcdsa.Y)
	childPoint := &ecdsa.PublicKey{Curve: parentEcdsa.Curve, X: childPointX, Y: childPointY}

	return encodeCompressedPublicKey(childPoint), nil
}

// encodeCompressedPublicKey encodes an ECDSA public key in compressed format.
func encodeCompressedPublicKey(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02 // Assume even Y
	if pub.Y.Bit(0) != 0 {
		compressed[0] = 0x03 // Odd Y
	}
	pub.X.FillBytes(compressed[1:])
	return compressed
}
