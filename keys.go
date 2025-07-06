package crypto

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// GenerateKeysFromMnemonic converts a BIP39 mnemonic phrase into secp256k1 private/public key pair
// with flexible BIP44 derivation path parameters
//
// This is a more flexible version that allows specifying custom derivation paths
// rather than hardcoded values, enabling support for:
// - Multiple cryptocurrencies (Bitcoin, Ethereum, Tron, etc.)
// - Multiple accounts per coin
// - Both receiving and change addresses
// - Any address index in the sequence
//
// Parameters:
// - mnemonic: BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
// - coin: Coin type from SLIP-0044 registry (e.g., 0 for Bitcoin, 60 for Ethereum, 195 for Tron)
// - account: Account index (usually 0 for first account)
// - chain: 0 for external chain (receiving), 1 for internal chain (change)
// - address: Address index (0, 1, 2, ... for sequential addresses)
func GenerateKeysFromMnemonic(mnemonic string, coin, account, chain, address uint32) (*secp256k1.PrivateKey,
	*secp256k1.PublicKey, error) {

	// Step 1: Validate mnemonic phrase integrity
	// Comprehensive BIP39 validation includes:
	// - Word count verification (must be 12, 15, 18, 21, or 24 words)
	// - Dictionary validation (all words must exist in BIP39 wordlist)
	// - Checksum verification (prevents typos and corruption)
	// - Entropy validation (ensures proper randomness distribution)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("invalid mnemonic")
	}

	// Step 2: Convert mnemonic to cryptographic seed
	// PBKDF2 key derivation function with BIP39 parameters:
	// - Password: The mnemonic phrase (normalized to NFKD Unicode)
	// - Salt: "mnemonic" + optional passphrase (empty string = no passphrase)
	// - Iterations: 2048 (balances security vs performance)
	// - Hash function: HMAC-SHA512
	// - Output length: 512 bits (64 bytes)
	//
	// The empty passphrase ("") is standard for most wallet implementations
	// Using a passphrase creates a completely different wallet tree
	seed := bip39.NewSeed(mnemonic, "")

	// Step 3: Generate BIP32 master key from seed
	// Creates the root node of the hierarchical deterministic key tree
	// Master key structure:
	// - Private key: 32 bytes of key material
	// - Chain code: 32 bytes for child key derivation
	// - Depth: 0 (master level)
	// - Parent fingerprint: 0x00000000 (no parent)
	// - Child index: 0x00000000 (not applicable)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, nil, err
	}

	// Step 4: Derive specific key using flexible BIP44 path
	// Full derivation path: m/44'/coin'/account'/chain/address
	//
	// IMPORTANT: The caller must provide properly formatted parameters:
	// - coin: Should include hardened bit (0x80000000) for BIP44 compliance
	// - account: Should include hardened bit (0x80000000) for BIP44 compliance
	// - chain: Should NOT include hardened bit (0 or 1 only)
	// - address: Should NOT include hardened bit (0, 1, 2, ...)
	//
	// Example for Bitcoin first receiving address:
	// - coin = 0x80000000 (Bitcoin + hardened)
	// - account = 0x80000000 (first account + hardened)
	// - chain = 0 (external/receiving addresses)
	// - address = 0 (first address)
	//
	// Example for Ethereum second change address:
	// - coin = 0x8000003C (Ethereum 60 + hardened)
	// - account = 0x80000000 (first account + hardened)
	// - chain = 1 (internal/change addresses)
	// - address = 1 (second address)
	key, err := DeriveKeyFromPath(masterKey, coin, account, chain, address)
	if err != nil {
		return nil, nil, err
	}

	// Step 5: Convert BIP32 key to secp256k1 cryptographic key pair
	// secp256k1 elliptic curve is used by most major cryptocurrencies
	// Curve properties:
	// - Prime field: p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
	// - Order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	// - Generator point: G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

	// Create secp256k1 private key from the 32-byte BIP32 key material
	// The private key must be in range [1, n-1] where n is the curve order
	// This is virtually guaranteed with proper entropy but should be validated in production
	privateKey := secp256k1.PrivKeyFromBytes(key.Key)

	// Derive the corresponding public key using elliptic curve point multiplication
	// Public key = private key × generator point G
	// This operation is:
	// - Computationally easy: private key → public key
	// - Computationally infeasible: public key → private key (discrete logarithm problem)
	// - Deterministic: same private key always produces same public key
	publicKey := privateKey.PubKey()

	// Return the cryptographic key pair
	// Applications can use these keys for:
	// - Private key: Transaction signing, message authentication, key agreement
	// - Public key: Address generation, signature verification, identity verification
	// - Both: Elliptic curve Diffie-Hellman key exchange
	return privateKey, publicKey, nil
}
