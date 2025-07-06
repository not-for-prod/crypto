# Crypto Wallet Generator

Go library for generating cryptocurrency wallets using BIP39 and BIP44 standards

## Installation

```bash
go get github.com/your-username/crypto-wallet-generator
```

## Dependencies

```go
import (
    "github.com/tyler-smith/go-bip39"
    "github.com/tyler-smith/go-bip32"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "github.com/btcsuite/btcd/btcutil/base58"
    "golang.org/x/crypto/sha3"
)
```

## Quick Start

```go
func main() {
    // Generate a 12-word mnemonic (128 bits entropy)
    mnemonic, err := crypto.GenerateMnemonic(128)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Mnemonic: %s\n", mnemonic)
    
    // Generate TRON keys from mnemonic
    privateKey, publicKey, err := crypto.GenerateKeysFromMnemonic(
        mnemonic,
	    cointype.Tron,  // TRON coin type
        0,               // First account
        0,               // External chain (receiving addresses)
        0,               // First address
    )
    if err != nil {
        log.Fatal(err)
    }
    
    // Generate TRON address
    address := crypto.GenerateTronAddress(publicKey)
    fmt.Printf("TRON Address: %s\n", address)
    fmt.Printf("Private Key: %x\n", privateKey.Serialize())
    fmt.Printf("Public Key: %x\n", publicKey.SerializeCompressed())
}
```

## Supported Cryptocurrencies

Currently supported coin types:

| Cryptocurrency | Coin Type | Constant |
|---------------|-----------|----------|
| TRON          | 195       | `coin_type.Tron` |

*Note: The library can be extended to support additional cryptocurrencies by adding coin type constants and address generation functions.*

## Acknowledgments

- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic code for generating deterministic keys
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) - Multi-Account Hierarchy for Deterministic Wallets
- [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) - Registered coin types for BIP44

## Disclaimer

This library is for educational and development purposes. Always conduct thorough security audits before using in production environments with real funds. The authors are not responsible for any loss of funds due to security vulnerabilities or misuse of this library.