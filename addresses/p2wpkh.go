package addresses

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/bech32"
	ecies "github.com/ecies/go/v2"
	"github.com/sdoshi579/bitcoin-addresses/helpers"
)

// Pay to witness public key hash
func GetP2WPKHAddress(eccKeyPair ecies.PrivateKey) {
	xCoordinate := eccKeyPair.PublicKey.X.Bytes()
	prefix := byte(0x03)
	if eccKeyPair.PublicKey.Y.Bytes()[len(eccKeyPair.PublicKey.Y.Bytes())-1]&1 == 0 {
		prefix = byte(0x02)
	}
	compressedPubKey := append([]byte{prefix}, xCoordinate...)

	compressedPublicKeyCommitment, err := helpers.GetHash160(compressedPubKey)
	if err != nil {
		panic(err)
	}

	bech32Bytes, err := bech32.ConvertBits(compressedPublicKeyCommitment, 8, 5, true)
	if err != nil {
		panic(err)
	}

	// 00 is witness version
	// For checksum use BCH code
	bech32Address, err := bech32.Encode(chaincfg.MainNetParams.Bech32HRPSegwit, append([]byte{0x00}, bech32Bytes...))
	if err != nil {
		panic(err)
	}
	fmt.Printf("length of P2WPKH in bytes: %d\n", len(bech32Bytes)+1)
	fmt.Printf("P2WPKH address encoded in bech32: %s\n", bech32Address)
}
