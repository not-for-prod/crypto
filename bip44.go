package hdwallet

import "github.com/tyler-smith/go-bip32"

const (
	HardenedOffset uint32 = 0x80000000
	Purpose        uint32 = 44
)

// DeriveKeyFromPath derives a private key from a master key using BIP44 hierarchical deterministic derivation
// BIP44 defines a specific derivation path structure: m/purpose'/coin_type'/account'/change/address_index
// Where:
// - purpose: Always 44' (0x8000002C) for BIP44 compliance
// - coin_type: Registered coin type (e.g., 0' for Bitcoin, 60' for Ethereum)
// - account: Account index starting from 0' (allows multiple accounts per coin)
// - change: 0 for external chain (receiving addresses), 1 for internal chain (change addresses)
// - address_index: Address index starting from 0 (sequential address generation)
//
// The apostrophe (') indicates hardened derivation (adds 0x80000000 to the index)
// Hardened derivation provides additional security by making it impossible to derive
// the parent private key from a child private key and parent public key
func DeriveKeyFromPath(masterKey *bip32.Key, coin, account, chain, address uint32) (*bip32.Key, error) {
	// Step 1: Derive purpose level (m/44')
	// Purpose is hardened and set to 44 (0x8000002C) as per BIP44 specification
	// This level identifies that we're using BIP44 derivation standard
	child, err := masterKey.NewChildKey(Purpose + HardenedOffset)
	if err != nil {
		return nil, err
	}

	// Step 2: Derive coin type level (m/44'/coin_type')
	// Coin type is hardened and identifies the cryptocurrency
	// Examples: Bitcoin=0', Testnet=1', Litecoin=2', Ethereum=60'
	// Full list: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
	child, err = child.NewChildKey(coin + HardenedOffset)
	if err != nil {
		return nil, err
	}

	// Step 3: Derive account level (m/44'/coin_type'/account')
	// Account is hardened and allows users to segregate funds into multiple accounts
	// Accounts are numbered from 0' and should be used sequentially
	// This enables features like separate accounts for different purposes
	child, err = child.NewChildKey(account + HardenedOffset)
	if err != nil {
		return nil, err
	}

	// Step 4: Derive change level (m/44'/coin_type'/account'/change)
	// Change is NOT hardened (no apostrophe)
	// 0 = external chain (public addresses for receiving funds)
	// 1 = internal chain (change addresses for transaction outputs)
	// This separation helps with privacy and UTXO management
	child, err = child.NewChildKey(chain)
	if err != nil {
		return nil, err
	}

	// Step 5: Derive address index level (m/44'/coin_type'/account'/change/address_index)
	// Address index is NOT hardened and starts from 0
	// This is the final level that generates the actual private key for an address
	// Addresses should be generated sequentially to ensure proper wallet recovery
	child, err = child.NewChildKey(address)
	if err != nil {
		return nil, err
	}

	// Return the derived private key that can be used to:
	// - Generate the corresponding public key
	// - Create cryptocurrency addresses
	// - Sign transactions
	return child, nil
}
