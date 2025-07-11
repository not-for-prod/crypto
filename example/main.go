package main

import (
	"fmt"
	"log"

	"github.com/not-for-prod/hdwallet"
	cointype "github.com/not-for-prod/hdwallet/coin-type"
)

func main() {
	// Generate a 12-word mnemonic (128 bits entropy)
	mnemonic, err := hdwallet.GenerateMnemonic(128)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mnemonic: %s\n", mnemonic)

	// Generate TRON keys from mnemonic
	privateKey, publicKey, err := hdwallet.GenerateKeysFromMnemonic(
		mnemonic,
		cointype.Tron, // TRON coin type
		0,             // First account
		0,             // External chain (receiving addresses)
		0,             // First address
	)
	if err != nil {
		log.Fatal(err)
	}

	// Generate TRON address
	address := hdwallet.GenerateTronAddress(publicKey)
	fmt.Printf("TRON Address: %s\n", address)
	fmt.Printf("Private Key: %x\n", privateKey.Serialize())
	fmt.Printf("Public Key: %x\n", publicKey.SerializeCompressed())
}
