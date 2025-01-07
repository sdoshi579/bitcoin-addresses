package addresses

import (
	"fmt"

	"github.com/bitcoin-addresses/helpers"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/bech32"
	ecies "github.com/ecies/go/v2"
)

// Pay to tap root
func GetP2TRAddress(eccKeyPair ecies.PrivateKey) {
	xCoordinate := eccKeyPair.PublicKey.X.Bytes()
	tweak := helpers.TaggedHash("TapTweak", xCoordinate)
	tweakPointX, tweakPointY := eccKeyPair.Curve.ScalarBaseMult(tweak)
	tweakedPublicKeyX, _ := eccKeyPair.Curve.Add(tweakPointX, tweakPointY, eccKeyPair.PublicKey.X, eccKeyPair.PublicKey.Y)

	bech32Bytes, err := bech32.ConvertBits(tweakedPublicKeyX.Bytes(), 8, 5, true)
	if err != nil {
		panic(err)
	}

	bech32Address, err := helpers.Bech32mEncode(chaincfg.MainNetParams.Bech32HRPSegwit, append([]byte{0x01}, bech32Bytes...))
	if err != nil {
		panic(err)
	}
	fmt.Printf("P2TR address encoded in bech32m: %s\n", bech32Address)
}
