package addresses

import (
	"fmt"

	ecies "github.com/ecies/go/v2"
)

// Pay to Public Key Address
func GetP2PKAddress(eccKeyPair ecies.PrivateKey) {
	fmt.Printf("Uncompressed Public Key: %x\n", append(eccKeyPair.PublicKey.X.Bytes(), eccKeyPair.PublicKey.Y.Bytes()...))
}
