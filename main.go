package main

import (
	"encoding/hex"
	"fmt"

	ecies "github.com/ecies/go/v2"
	"github.com/sdoshi579/bitcoin-addresses/addresses"
	"github.com/sdoshi579/bitcoin-addresses/helpers"
)

func main() {
	privateKey, err := ecies.GenerateKey()
	if err != nil {
		fmt.Println("error: ", err)
	}

	publicKey := privateKey.PublicKey

	fmt.Println("Private Key (Hex): ", hex.EncodeToString(privateKey.D.Bytes()))

	fmt.Println("x co-ordinate of public key: ", publicKey.X)
	fmt.Println("y co-ordinate of public key: ", publicKey.Y)

	fmt.Println("x co-ordinate of public key in hex: ", hex.EncodeToString(publicKey.X.Bytes()))
	fmt.Println("y co-ordinate of public key in hex: ", hex.EncodeToString(publicKey.Y.Bytes()))

	addresses.GetP2PKHAddress(*privateKey)

	addresses.GetP2SHAddress(*privateKey)

	addresses.GetP2WPKHAddress(*privateKey)

	addresses.GetP2TRAddress(*privateKey)

	entropy, err := addresses.GetEntropy(128)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Printf("Entropy: %v\n", hex.EncodeToString(entropy))

	recoverCodes := addresses.GetRecoveryCodesFromEntropy(entropy)
	fmt.Printf("Recovery code: %v\n", recoverCodes)

	seed := addresses.GetSeedFromRecoveryCodes(recoverCodes, "")
	fmt.Printf("Seed: %x\n", seed)

	masterPrivateKey, masterChainCode := addresses.GetMasterPrivateKeyAndMasterChainCodeFromSeed(seed)

	fmt.Printf("Master Private Key: %x\n, Master Chain Code: %x\n ", masterPrivateKey, masterChainCode)

	masterPublicKey := helpers.GetPublicKey(masterPrivateKey)
	fmt.Printf("Master Public Key: %x\n", masterPublicKey)

	hardenedChildPrivateKey, hardenedChildChainCode, err := addresses.GetChildHardenedKey(masterPrivateKey, masterChainCode, "m/0'")
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	fmt.Printf("first hardened key: %x,\n chain code: %x, index: 2^31\n", hardenedChildPrivateKey, hardenedChildChainCode)

	fmt.Printf("public key of first hardened key: %x\n", helpers.GetPublicKey(hardenedChildPrivateKey))

	normalChildPrivateKey, normalChildChainCode, _ := addresses.GetChildNormalKey(masterPrivateKey, masterPublicKey, masterChainCode, "m/0")
	fmt.Printf("first normal key: %x,\n chain code: %x, index: 2^31\n", normalChildPrivateKey, normalChildChainCode)

	fmt.Printf("public key of first norma key: %x\n", helpers.GetPublicKey(normalChildPrivateKey))

	normalChildPublicKey, normalChildChainCode, _ := addresses.GetNormalPublicKey(masterPublicKey, masterChainCode, "m/0")
	fmt.Printf("first normal public key: %x,\n chain code: %x, index: 2^31\n", normalChildPublicKey, normalChildChainCode)

	getChildKeysForPath(masterPrivateKey, masterChainCode)
}

func getChildKeysForPath(masterPrivateKey, masterChainCode []byte) {
	req := addresses.KeyDerivationRequest{
		MasterPrivateKey: masterPrivateKey,
		MasterChainCode:  masterChainCode,
		Path:             "m/0/0/0'",
	}

	resp, err := addresses.GetChildKeyFromPath(req)
	if err != nil {
		fmt.Println("Error deriving key from path:", err)
		return
	}

	fmt.Printf("Derived key for path %s:\n", resp.Path)
	fmt.Printf("Private Key: %x\n", resp.PrivateKey)
	fmt.Printf("Public Key: %x\n", resp.PublicKey)
	fmt.Printf("Chain Code: %x\n", resp.ChainCode)
}
