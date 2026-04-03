# bip39lib

Pure Python BIP39 mnemonic code library for generating deterministic wallet seeds.

[![PyPI](https://img.shields.io/pypi/v/bip39lib.svg)](https://pypi.org/project/bip39lib/)
[![Python](https://img.shields.io/pypi/pyversions/bip39lib.svg)](https://pypi.org/project/bip39lib/)

## Install

```bash
pip install bip39lib
```

## Usage

```python
from bip39lib import generate_mnemonic, mnemonic_to_seed, validate_mnemonic

# Generate a 12-word mnemonic (128 bits of entropy)
mnemonic = generate_mnemonic()
print(mnemonic)  # abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

# Validate the mnemonic
is_valid = validate_mnemonic(mnemonic)
print(is_valid)  # True

# Convert mnemonic to seed (for HD wallet derivation)
seed = mnemonic_to_seed(mnemonic, passphrase="")
print(seed.hex())  # 64-byte seed
```

## API

- `generate_mnemonic(entropy_bits: int = 128, wordlist: list[str] | None = None) -> str` - Generate mnemonic from entropy
- `mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes` - Convert mnemonic to seed
- `validate_mnemonic(mnemonic: str, wordlist: list[str] | None = None) -> bool` - Validate mnemonic checksum
- `entropy_to_mnemonic(entropy: bytes, wordlist: list[str] | None = None) -> str` - Convert entropy to mnemonic
- `mnemonic_to_entropy(mnemonic: str, wordlist: list[str] | None = None) -> bytes` - Convert mnemonic to entropy
- `get_wordlist(lang: str = "en") -> list[str]` - Get BIP39 wordlist by language

## Development

```bash
git clone https://github.com/daedalus/bip39lib.git
cd bip39lib
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```
