package helpers

import (
	ecies "github.com/ecies/go/v2"
)

func GetEccKeyPair() ecies.PrivateKey {
	privateKey, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}

	return *privateKey
}

func GetPublicKey(privateKey []byte) []byte {
	privateKeyInstance := ecies.NewPrivateKeyFromBytes(privateKey)

	return privateKeyInstance.PublicKey.Bytes(true)
}
