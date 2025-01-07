package addresses

import (
	"fmt"

	"github.com/bitcoin-addresses/helpers"
	"github.com/btcsuite/btcutil/base58"
	ecies "github.com/ecies/go/v2"
)

// Pay to Script Hash Address
func GetP2SHAddress(eccKeyPair ecies.PrivateKey) {

	publicKey := append(eccKeyPair.PublicKey.X.Bytes(), eccKeyPair.PublicKey.Y.Bytes()...)

	publicKeyCommitment, err := helpers.GetHash160(publicKey)

	if err != nil {
		panic(err)
	}

	// outputScript := "OP_HASH160 OP_PUSHBYTES_20 %x OP_EQUAL"
	// Opcodes to hexcode mapping https://github.com/bcoin-org/bcoin/blob/master/lib/script/common.js
	outputScriptInBytes := append(append([]byte{0xa9, 0x14}, publicKeyCommitment...), byte(0x87))
	scriptCommitment, err := helpers.GetHash160(outputScriptInBytes)
	if err != nil {
		panic(err)
	}
	version := byte(0x05)
	checksum := helpers.GetChecksum(append([]byte{version}, scriptCommitment...))

	fmt.Printf("P2SH address: %s\n", base58.Encode(append(append([]byte{version}, scriptCommitment...), checksum[:4]...)))
}
