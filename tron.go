package hdwallet

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// GenerateTronAddress generates a TRON address from a secp256k1 public key
// TRON addresses are similar to Ethereum addresses but use a different prefix and encoding
// The process follows these steps:
// 1. Extract uncompressed public key coordinates
// 2. Hash using Keccak-256 (same as Ethereum)
// 3. Take last 20 bytes and add TRON prefix (0x41)
// 4. Add double SHA-256 checksum
// 5. Encode in Base58 format
//
// TRON addresses always start with 'T' when encoded and are 34 characters long
// Example: TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy
func GenerateTronAddress(publicKey *secp256k1.PublicKey) string {
	// Step 1: Extract public key coordinates (remove compression prefix)
	// SerializeUncompressed() returns 65 bytes: [0x04][32-byte X][32-byte Y]
	// We skip the first byte (0x04 prefix) to get the raw 64-byte coordinates
	// This is the same format used by Ethereum for address generation
	pubKeyBytes := publicKey.SerializeUncompressed()[1:]

	// Step 2: Hash the public key coordinates using Keccak-256
	// Keccak-256 is the cryptographic hash function used by Ethereum and TRON
	// It's different from SHA-3 despite being from the same family
	// The "Legacy" version matches the original Keccak specification used by Ethereum
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashBytes := hash.Sum(nil)

	// Step 3: Create TRON address from hash
	// Take the last 20 bytes of the Keccak-256 hash (same as Ethereum)
	// Prepend with 0x41 byte (TRON's network identifier)
	// 0x41 = 65 in decimal, which makes addresses start with 'T' in Base58
	// This is equivalent to Ethereum's address format but with different prefix:
	// - Ethereum: 0x + 20 bytes (hex encoding)
	// - TRON: 0x41 + 20 bytes (Base58 encoding)
	addressBytes := append([]byte{0x41}, hashBytes[len(hashBytes)-20:]...)

	// Step 4: Generate checksum using double SHA-256
	// TRON uses Bitcoin-style double SHA-256 checksum instead of Ethereum's approach
	// This provides integrity checking to detect transcription errors
	// First SHA-256 hash of the address bytes
	firstHash := sha256.Sum256(addressBytes)
	// Second SHA-256 hash of the first hash result
	secondHash := sha256.Sum256(firstHash[:])

	// Step 5: Append first 4 bytes of double hash as checksum
	// The checksum allows wallets to validate address integrity
	// Invalid addresses will fail checksum verification
	// This prevents sending funds to malformed addresses
	addressWithChecksum := append(addressBytes, secondHash[:4]...)

	// Step 6: Encode in Base58 format
	// Base58 encoding (Bitcoin alphabet) makes addresses human-readable
	// Base58 excludes confusing characters: 0 (zero), O (capital o), I (capital i), l (lower L)
	// The 0x41 prefix ensures TRON addresses always start with 'T'
	// Final format: 34-character string starting with 'T'
	// Example: TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy
	return base58.Encode(addressWithChecksum)
}
