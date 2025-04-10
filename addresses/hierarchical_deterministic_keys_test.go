package addresses

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGetEntropy(t *testing.T) {
	tests := []struct {
		allowedBits int
		expectError bool
	}{
		{128, false},
		{256, false},
		{64, true},  // Invalid bits
		{300, true}, // Invalid bits
	}

	for _, test := range tests {
		entropy, err := GetEntropy(test.allowedBits)
		if test.expectError {
			if err == nil {
				t.Errorf("Expected error for allowedBits %d, but got none", test.allowedBits)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for allowedBits %d: %v", test.allowedBits, err)
			}
			if len(entropy)*8 != test.allowedBits {
				t.Errorf("Expected entropy length %d bits, got %d bits", test.allowedBits, len(entropy)*8)
			}
		}
	}
}

func TestGetRecoveryCodesFromEntropy(t *testing.T) {
	entropy, _ := hex.DecodeString("58fff21999a3ceed9accfdff5461a0ea")
	expectedCodes := []string{"flight", "zebra", "major", "crew", "diagram", "item", "hen", "panic", "young", "perfect", "habit", "stick"}

	recoveryCodes := GetRecoveryCodesFromEntropy(entropy)
	if len(recoveryCodes) != len(expectedCodes) {
		t.Fatalf("Expected %d recovery codes, got %d", len(expectedCodes), len(recoveryCodes))
	}

	for i, code := range recoveryCodes {
		if code != expectedCodes[i] {
			t.Errorf("Expected recovery code %s, got %s", expectedCodes[i], code)
			break
		}
	}
}

func TestGetSeedFromRecoveryCodes(t *testing.T) {
	recoveryCodes := []string{"flight", "zebra", "major", "crew", "diagram", "item", "hen", "panic", "young", "perfect", "habit", "stick"}
	salt := ""
	expectedSeed := "03b37261347e3bc89b5174bb06c1ec4206a4bc6373ed437ce889bbaae64e83fd55302d6621db444fe678cf52f78f5cd6293219b5f733e0dc0f13193818871180"

	seed := GetSeedFromRecoveryCodes(recoveryCodes, salt)
	if hex.EncodeToString(seed) != expectedSeed {
		t.Errorf("Expected seed %s, got %s", expectedSeed, hex.EncodeToString(seed))
	}
}

func TestGetMasterPrivateKeyAndMasterChainCodeFromSeed(t *testing.T) {
	seed, _ := hex.DecodeString("03b37261347e3bc89b5174bb06c1ec4206a4bc6373ed437ce889bbaae64e83fd55302d6621db444fe678cf52f78f5cd6293219b5f733e0dc0f13193818871180")
	expectedPrivateKey := "a4699561d1b2bcc30af927e87b7e87becd31b802a1add612ed2286a225051f7f"
	expectedChainCode := "6afac9499be36e81f209f2661227934b5bc54431b5fd5b43d1bcaf36c25f6056"

	privateKey, chainCode := GetMasterPrivateKeyAndMasterChainCodeFromSeed(seed)
	if hex.EncodeToString(privateKey) != expectedPrivateKey {
		t.Errorf("Expected private key %s, got %s", expectedPrivateKey, hex.EncodeToString(privateKey))
	}
	if hex.EncodeToString(chainCode) != expectedChainCode {
		t.Errorf("Expected chain code %s, got %s", expectedChainCode, hex.EncodeToString(chainCode))
	}
}

func TestGetChildHardenedKey(t *testing.T) {
	masterPrivateKey, _ := hex.DecodeString("a4699561d1b2bcc30af927e87b7e87becd31b802a1add612ed2286a225051f7f")
	masterChainCode, _ := hex.DecodeString("6afac9499be36e81f209f2661227934b5bc54431b5fd5b43d1bcaf36c25f6056")
	path := "m/0'"

	childPrivateKey, childChainCode, err := GetChildHardenedKey(masterPrivateKey, masterChainCode, path)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedChildPrivateKey := "e873816df40757497acbc38d7f4b672a67659a0ffa431a668ceb356d7c82c252"
	expectedChildChainCode := "86f05bf8cedbd92821ff064aeaf5f0ed8813aab9df5a25c56449595529255d13"

	if hex.EncodeToString(childPrivateKey) != expectedChildPrivateKey {
		t.Errorf("Expected child private key %s, got %s", expectedChildPrivateKey, hex.EncodeToString(childPrivateKey))
	}
	if hex.EncodeToString(childChainCode) != expectedChildChainCode {
		t.Errorf("Expected child chain code %s, got %s", expectedChildChainCode, hex.EncodeToString(childChainCode))
	}
}

func TestGetChildNormalKey(t *testing.T) {
	masterPrivateKey, _ := hex.DecodeString("a4699561d1b2bcc30af927e87b7e87becd31b802a1add612ed2286a225051f7f")
	masterPublicKey, _ := hex.DecodeString("02ebb3939811d472a0475c6f400bac443bf460a63356d970715570e71d9311dad5")
	masterChainCode, _ := hex.DecodeString("6afac9499be36e81f209f2661227934b5bc54431b5fd5b43d1bcaf36c25f6056")
	path := "m/0"

	childPrivateKey, childChainCode, err := GetChildNormalKey(masterPrivateKey, masterPublicKey, masterChainCode, path)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedChildPrivateKey := "b889d963d473c6cb367f4f512c5fd1892eb10aae2393fbd6b8967252302b6335"
	expectedChildChainCode := "cce153d6c557681967e242cd394e6fdc216adc5b8f772b1906a634f2fda88b48"

	if hex.EncodeToString(childPrivateKey) != expectedChildPrivateKey {
		t.Errorf("Expected child private key %s, got %s", expectedChildPrivateKey, hex.EncodeToString(childPrivateKey))
	}
	if hex.EncodeToString(childChainCode) != expectedChildChainCode {
		t.Errorf("Expected child chain code %s, got %s", expectedChildChainCode, hex.EncodeToString(childChainCode))
	}
}

func TestGetNormalPublicKey(t *testing.T) {
	masterPublicKey, _ := hex.DecodeString("02ebb3939811d472a0475c6f400bac443bf460a63356d970715570e71d9311dad5")
	masterChainCode, _ := hex.DecodeString("6afac9499be36e81f209f2661227934b5bc54431b5fd5b43d1bcaf36c25f6056")
	path := "m/0"

	childPublicKey, childChainCode, err := GetNormalPublicKey(masterPublicKey, masterChainCode, path)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedChildPublicKey := "026e4ca2373932a0b06eb16f0295d6178446d32cac3444766e609967119c7c5d99"
	expectedChildChainCode := "cce153d6c557681967e242cd394e6fdc216adc5b8f772b1906a634f2fda88b48"

	if hex.EncodeToString(childPublicKey) != expectedChildPublicKey {
		t.Errorf("Expected child public key %s, got %s", expectedChildPublicKey, hex.EncodeToString(childPublicKey))
	}
	if hex.EncodeToString(childChainCode) != expectedChildChainCode {
		t.Errorf("Expected child chain code %s, got %s", expectedChildChainCode, hex.EncodeToString(childChainCode))
	}
}

func getChildKeysForPath(masterPrivateKey, masterChainCode []byte) {
	req := KeyDerivationRequest{
		MasterPrivateKey: masterPrivateKey,
		MasterChainCode:  masterChainCode,
		Path:             "m/0/0/0'",
	}

	resp, err := GetChildKeyFromPath(req)
	if err != nil {
		fmt.Println("Error deriving key from path:", err)
		return
	}

	// Expected values
	expectedPrivateKey := "bd3051169a6573c1d1ea298f826fb61b42f39a15bfa8f0d3e1be85de65825a8c"
	expectedPublicKey := "0370999eae627353ceb0d58fd559058dc2060fa7bc146a681c6021d22dd133165e"
	expectedChainCode := "8f9c7f328741049d589f2e26bbf81c9c1d34bfd3737cb6596614d94cd2695a6c"

	// Print derived values
	fmt.Printf("Derived key for path %s:\n", resp.Path)
	fmt.Printf("Private Key: %x\n", resp.PrivateKey)
	fmt.Printf("Public Key: %x\n", resp.PublicKey)
	fmt.Printf("Chain Code: %x\n", resp.ChainCode)

	// Validate derived values against expected values
	if hex.EncodeToString(resp.PrivateKey) != expectedPrivateKey {
		fmt.Printf("Mismatch in Private Key! Expected: %s, Got: %x\n", expectedPrivateKey, resp.PrivateKey)
	} else {
		fmt.Println("Private Key matches expected value.")
	}

	if hex.EncodeToString(resp.PublicKey) != expectedPublicKey {
		fmt.Printf("Mismatch in Public Key! Expected: %s, Got: %x\n", expectedPublicKey, resp.PublicKey)
	} else {
		fmt.Println("Public Key matches expected value.")
	}

	if hex.EncodeToString(resp.ChainCode) != expectedChainCode {
		fmt.Printf("Mismatch in Chain Code! Expected: %s, Got: %x\n", expectedChainCode, resp.ChainCode)
	} else {
		fmt.Println("Chain Code matches expected value.")
	}
}
