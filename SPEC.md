# SPEC.md — bip39lib

## Purpose

A pure Python library implementing BIP39 (Mnemonic Code for Generating Deterministic Keys). Provides functions to generate mnemonic phrases from entropy, convert mnemonics to binary seeds, and validate mnemonics against checksums. Designed for cryptocurrency wallet key generation.

## Scope

### In Scope
- Mnemonic generation from random entropy (128-256 bits in 32-bit increments)
- Mnemonic to seed conversion using PBKDF2 with HMAC-SHA512
- Validation of mnemonic checksums
- Support for English wordlist (BIP39 standard)
- Seed derivation with optional passphrase

### Not In Scope
- HD wallet derivation (BIP32)
- Key generation from seeds
- Non-English wordlists
- GUI/CLI interface (library only)
- Wallet import/export formats

## Public API

### `generate_mnemonic(entropy_bits: int = 128, wordlist: list[str] | None = None) -> str`
Generate a mnemonic phrase from random entropy.

- `entropy_bits`: Entropy length in bits (128, 160, 192, 224, or 256)
- `wordlist`: Optional custom wordlist (defaults to English BIP39 wordlist)
- Returns: Space-separated mnemonic words
- Raises: `ValueError` if entropy_bits not in valid range

### `mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes`
Convert mnemonic to binary seed using PBKDF2.

- `mnemonic`: Space-separated mnemonic words
- `passphrase`: Optional passphrase (default empty string)
- Returns: 64-byte binary seed
- Raises: `ValueError` if mnemonic invalid

### `validate_mnemonic(mnemonic: str, wordlist: list[str] | None = None) -> bool`
Validate mnemonic checksum.

- `mnemonic`: Space-separated mnemonic words
- `wordlist`: Optional custom wordlist
- Returns: True if valid, False otherwise

### `entropy_to_mnemonic(entropy: bytes, wordlist: list[str] | None = None) -> str`
Convert entropy bytes to mnemonic.

- `entropy`: Entropy bytes (16, 20, 24, 28, or 32 bytes)
- `wordlist`: Optional custom wordlist
- Returns: Space-separated mnemonic words
- Raises: `ValueError` if entropy length invalid

### `mnemonic_to_entropy(mnemonic: str, wordlist: list[str] | None = None) -> bytes`
Convert mnemonic to entropy bytes.

- `mnemonic`: Space-separated mnemonic words
- `wordlist`: Optional custom wordlist
- Returns: Entropy bytes (without checksum)
- Raises: `ValueError` if mnemonic invalid

### `get_wordlist(lang: str = "en") -> list[str]`
Get BIP39 wordlist by language.

- `lang`: Language code (currently only "en" supported)
- Returns: List of 2048 words

## Data Formats

- **Entropy**: bytes of length 16, 20, 24, 28, or 32 (128-256 bits in 32-bit steps)
- **Mnemonic**: space-separated words (12, 15, 18, 21, or 24 words)
- **Seed**: 64 bytes (512 bits)
- **Passphrase**: arbitrary string (UTF-8 NFKD)

## Edge Cases

1. Empty passphrase should produce valid seed
2. Invalid entropy length (not 16/20/24/28/32 bytes) raises ValueError
3. Invalid word count (not 12/15/18/21/24) raises ValueError
4. Unknown word in mnemonic raises ValueError
5. Checksum mismatch raises ValueError
6. Whitespace normalization in mnemonic (multiple spaces -> single space, trim)
7. Passphrase with Unicode characters (NFKD normalization)
8. Very long passphrases should work (no practical limit)

## Performance & Constraints

- Pure Python with no external dependencies (uses stdlib only)
- PBKDF2 with 2048 iterations (as per BIP39 spec)
- Memory efficient - wordlist loaded on demand
- Target: Python 3.11+
