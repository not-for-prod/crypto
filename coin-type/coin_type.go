// Package cointype provides constants for registered cryptocurrency coin types
// as defined in BIP44 (Bitcoin Improvement Proposal 44).
//
// BIP44 defines a logical hierarchy for deterministic wallets based on an algorithm
// described in BIP32, and purpose scheme described in BIP43. Each cryptocurrency
// is assigned a unique coin type number to ensure proper key derivation paths.
//
// The coin type constants in this package correspond to the official registry
// maintained at: https://github.com/satoshilabs/slips/blob/master/slip-0044.md

package cointype

const (
	Tron = 159
)
