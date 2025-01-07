package main

import (
	"encoding/hex"
	"fmt"

	"github.com/bitcoin-addresses/addresses"
	ecies "github.com/ecies/go/v2"
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
}
