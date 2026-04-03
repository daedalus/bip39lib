import hashlib
import hmac
import secrets
import unicodedata
import urllib.request

url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
with urllib.request.urlopen(url) as response:
    content = response.read().decode("utf-8")

words = [w.strip() for w in content.splitlines() if w.strip()]

_WORDLIST_EN = words

_VALID_ENTROPY_BITS = (128, 160, 192, 224, 256)
_VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


def get_wordlist(lang: str = "en") -> list[str]:
    if lang == "en":
        return _WORDLIST_EN.copy()
    msg = f"Language '{lang}' not supported"
    raise ValueError(msg)


def _pbkdf2(password: bytes, salt: bytes, iterations: int, keylen: int) -> bytes:
    def prf(p: bytes, s: bytes) -> bytes:
        return hmac.new(p, s, hashlib.sha512).digest()

    block = bytearray()
    i = 1

    while len(block) < keylen:
        U = prf(password, salt + i.to_bytes(4, "big"))  # noqa: N806
        f = bytearray(U)
        for _ in range(1, iterations):
            U = prf(password, bytes(U))  # noqa: N806
            for j in range(len(f)):
                f[j] ^= U[j]
        block.extend(f)
        i += 1

    return bytes(block[:keylen])


def _normalize_nfkd(s: str) -> str:
    return unicodedata.normalize("NFKD", s)


def generate_mnemonic(
    entropy_bits: int = 128, wordlist: list[str] | None = None
) -> str:
    if entropy_bits not in _VALID_ENTROPY_BITS:
        msg = f"Invalid entropy bits: {entropy_bits}. Must be one of {_VALID_ENTROPY_BITS}"
        raise ValueError(msg)

    entropy = secrets.token_bytes(entropy_bits // 8)
    return entropy_to_mnemonic(entropy, wordlist)


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str] | None = None) -> str:
    entropy_len = len(entropy)
    if entropy_len not in (16, 20, 24, 28, 32):
        msg = f"Invalid entropy length: {entropy_len}. Must be one of (16, 20, 24, 28, 32)"
        raise ValueError(msg)

    if wordlist is None:
        wordlist = _WORDLIST_EN

    checksum = hashlib.sha256(entropy).digest()[0]
    checksum_bits = entropy_len // 4

    entropy_int = int.from_bytes(entropy, "big")
    checksum_val = checksum >> (8 - checksum_bits)

    bits = (entropy_int << checksum_bits) | checksum_val

    word_count = (entropy_len * 8 + checksum_bits) // 11
    words_out: list[str] = []

    for i in range(word_count):
        idx = (bits >> (11 * (word_count - 1 - i))) & 0x7FF
        words_out.append(wordlist[idx])

    return " ".join(words_out)


def mnemonic_to_entropy(mnemonic: str, wordlist: list[str] | None = None) -> bytes:
    words = mnemonic.split()

    if not words:
        msg = "Mnemonic is empty"
        raise ValueError(msg)

    word_count = len(words)
    if word_count not in _VALID_WORD_COUNTS:
        msg = f"Invalid word count: {word_count}. Must be one of {_VALID_WORD_COUNTS}"
        raise ValueError(msg)

    if wordlist is None:
        wordlist = _WORDLIST_EN

    word_indices: list[int] = []
    for word in words:
        try:
            idx = wordlist.index(word)
        except ValueError:
            msg = f"Unknown word: '{word}'"
            raise ValueError(msg) from None
        word_indices.append(idx)

    total_bits = word_count * 11
    entropy_bits = total_bits * 32 // 33
    checksum_bits = total_bits - entropy_bits
    entropy_bytes = entropy_bits // 8

    bits = 0
    for idx in word_indices:
        bits = (bits << 11) | idx

    bits >>= checksum_bits
    entropy = int(bits).to_bytes(entropy_bytes, "big")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic_normalized = _normalize_nfkd(mnemonic)
    passphrase_normalized = _normalize_nfkd(passphrase)

    salt = b"mnemonic" + passphrase_normalized.encode("utf-8")
    seed = _pbkdf2(
        password=mnemonic_normalized.encode("utf-8"),
        salt=salt,
        iterations=2048,
        keylen=64,
    )
    return seed


def validate_mnemonic(mnemonic: str, wordlist: list[str] | None = None) -> bool:
    try:
        entropy = mnemonic_to_entropy(mnemonic, wordlist)
        expected_mnemonic = entropy_to_mnemonic(entropy, wordlist)
        return mnemonic == expected_mnemonic
    except ValueError:
        return False
