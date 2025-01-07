package addresses

import (
	"fmt"

	"github.com/bitcoin-addresses/helpers"
	"github.com/btcsuite/btcutil/base58"
	ecies "github.com/ecies/go/v2"
)

// Pay to Public Key Hash Address
func GetP2PKHAddress(eccKeyPair ecies.PrivateKey) {
	publicKey := append(eccKeyPair.PublicKey.X.Bytes(), eccKeyPair.PublicKey.Y.Bytes()...)

	publicKeyCommitment, err := helpers.GetHash160(publicKey)

	if err != nil {
		panic(err)
	}

	version := byte(0x00) // For mainnet for testnet use 6f
	checksum := helpers.GetChecksum(append([]byte{version}, publicKeyCommitment...))

	fmt.Printf("P2PKH address: %s\n", "1"+base58.Encode(append(publicKeyCommitment, checksum[:4]...)))
}
