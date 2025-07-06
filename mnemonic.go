package crypto

import "github.com/tyler-smith/go-bip39"

// GenerateMnemonic creates a new BIP39 mnemonic phrase for wallet seed generation
// BIP39 defines a method for generating deterministic wallets using human-readable words
// The mnemonic acts as a master seed that can regenerate all wallet keys deterministically
//
// Security considerations:
// - The entropy must be cryptographically secure and truly random
// - Mnemonic phrases should be stored securely and never transmitted over insecure channels
// - Loss of the mnemonic means permanent loss of wallet access
// - The mnemonic can regenerate the entire wallet hierarchy across different applications
func GenerateMnemonic(bitSize int) (string, error) {
	// Step 1: Generate cryptographically secure entropy
	// 128 bits of entropy = 12 word mnemonic phrase
	// Other common options:
	// - 160 bits = 15 words (rarely used)
	// - 192 bits = 18 words (rarely used)
	// - 224 bits = 21 words (rarely used)
	// - 256 bits = 24 words (more secure, commonly used for high-value wallets)
	//
	// 128 bits provides 2^128 possible combinations, which is cryptographically secure
	// against brute force attacks (approximately 10^38 combinations)
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		// Entropy generation failure is a critical error that should never happen
		// in normal operation. It could indicate:
		// - Insufficient system entropy
		// - Hardware/OS random number generator failure
		// - Memory allocation issues
		return "", err
	}

	// Step 2: Convert entropy to mnemonic phrase
	// The entropy is processed through BIP39 algorithm:
	// 1. A checksum is calculated from the entropy (entropy_length/32 bits)
	// 2. Checksum is appended to entropy
	// 3. The combined bits are split into 11-bit groups
	// 4. Each 11-bit group maps to a word from the BIP39 wordlist (2048 words)
	// 5. For 128-bit entropy: 128 + 4 checksum = 132 bits = 12 groups = 12 words
	//
	// The checksum ensures mnemonic integrity - invalid mnemonics can be detected
	// without needing to derive keys, providing early error detection
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		// Mnemonic generation failure should be extremely rare and indicates:
		// - Invalid entropy format (should not happen with proper entropy generation)
		// - Memory issues
		// - Library corruption
		return "", err
	}

	// Return the mnemonic phrase
	// Format: 12 space-separated words from the BIP39 wordlist
	// Example: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// The mnemonic can be used to:
	// - Regenerate the master seed using PBKDF2 (optionally with passphrase)
	// - Restore the entire wallet hierarchy
	// - Import into any BIP39-compatible wallet
	return mnemonic, nil
}
