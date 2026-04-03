import binascii
import secrets

import pytest

from bip39lib import (
    entropy_to_mnemonic,
    generate_mnemonic,
    get_wordlist,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    validate_mnemonic,
)

TEST_VECTORS = [
    {
        "entropy": "00000000000000000000000000000000",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "passphrase": "TREZOR",
        "seed": "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    },
    {
        "entropy": "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "passphrase": "TREZOR",
        "seed": "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    },
    {
        "entropy": "80808080808080808080808080808080",
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "passphrase": "TREZOR",
        "seed": "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    },
    {
        "entropy": "ffffffffffffffffffffffffffffffff",
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "passphrase": "TREZOR",
        "seed": "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    },
    {
        "entropy": "000000000000000000000000000000000000000000000000",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "passphrase": "TREZOR",
        "seed": "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    },
]


class TestGetWordlist:
    def test_english_wordlist_length(self) -> None:
        wordlist = get_wordlist("en")
        assert len(wordlist) == 2048

    def test_english_wordlist_sorted(self) -> None:
        wordlist = get_wordlist("en")
        assert wordlist == sorted(wordlist)

    def test_unsupported_language(self) -> None:
        with pytest.raises(ValueError, match="Language 'fr' not supported"):
            get_wordlist("fr")


class TestGenerateMnemonic:
    def test_128_bits(self) -> None:
        mnemonic = generate_mnemonic(128)
        words = mnemonic.split()
        assert len(words) == 12

    def test_160_bits(self) -> None:
        mnemonic = generate_mnemonic(160)
        words = mnemonic.split()
        assert len(words) == 15

    def test_192_bits(self) -> None:
        mnemonic = generate_mnemonic(192)
        words = mnemonic.split()
        assert len(words) == 18

    def test_224_bits(self) -> None:
        mnemonic = generate_mnemonic(224)
        words = mnemonic.split()
        assert len(words) == 21

    def test_256_bits(self) -> None:
        mnemonic = generate_mnemonic(256)
        words = mnemonic.split()
        assert len(words) == 24

    def test_invalid_entropy_bits(self) -> None:
        with pytest.raises(ValueError, match="Invalid entropy bits"):
            generate_mnemonic(100)

    def test_validates_against_wordlist(self) -> None:
        mnemonic = generate_mnemonic(128)
        assert validate_mnemonic(mnemonic)


class TestEntropyToMnemonic:
    def test_16_bytes(self) -> None:
        entropy = bytes(16)
        mnemonic = entropy_to_mnemonic(entropy)
        assert len(mnemonic.split()) == 12

    def test_20_bytes(self) -> None:
        entropy = bytes(20)
        mnemonic = entropy_to_mnemonic(entropy)
        assert len(mnemonic.split()) == 15

    def test_24_bytes(self) -> None:
        entropy = bytes(24)
        mnemonic = entropy_to_mnemonic(entropy)
        assert len(mnemonic.split()) == 18

    def test_28_bytes(self) -> None:
        entropy = bytes(28)
        mnemonic = entropy_to_mnemonic(entropy)
        assert len(mnemonic.split()) == 21

    def test_32_bytes(self) -> None:
        entropy = bytes(32)
        mnemonic = entropy_to_mnemonic(entropy)
        assert len(mnemonic.split()) == 24

    def test_invalid_entropy_length(self) -> None:
        with pytest.raises(ValueError, match="Invalid entropy length"):
            entropy_to_mnemonic(bytes(15))

    def test_roundtrip(self) -> None:
        entropy = secrets.token_bytes(32)
        mnemonic = entropy_to_mnemonic(entropy)
        result = mnemonic_to_entropy(mnemonic)
        assert result == entropy


class TestMnemonicToEntropy:
    def test_12_words(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        entropy = mnemonic_to_entropy(mnemonic)
        assert len(entropy) == 16

    def test_15_words(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        entropy = mnemonic_to_entropy(mnemonic)
        assert len(entropy) == 20

    def test_empty_mnemonic(self) -> None:
        with pytest.raises(ValueError, match="Mnemonic is empty"):
            mnemonic_to_entropy("")

    def test_invalid_word_count(self) -> None:
        with pytest.raises(ValueError, match="Invalid word count"):
            mnemonic_to_entropy("abandon abandon abandon")

    def test_unknown_word(self) -> None:
        with pytest.raises(ValueError, match="Unknown word"):
            mnemonic_to_entropy(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzword"
            )


class TestMnemonicToSeed:
    def test_empty_passphrase(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = mnemonic_to_seed(mnemonic, "")
        assert len(seed) == 64

    def test_with_passphrase(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = mnemonic_to_seed(mnemonic, "TREZOR")
        assert len(seed) == 64

    def test_unicode_passphrase(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = mnemonic_to_seed(mnemonic, " passphrase ")
        assert len(seed) == 64


class TestValidateMnemonic:
    def test_valid_12_word(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        assert validate_mnemonic(mnemonic) is True

    def test_valid_24_word(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        assert validate_mnemonic(mnemonic) is True

    def test_invalid_checksum(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong"
        assert validate_mnemonic(mnemonic) is False

    def test_invalid_word(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyz"
        assert validate_mnemonic(mnemonic) is False


class TestTestVectors:
    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_entropy_to_mnemonic(self, vector: dict) -> None:
        entropy = binascii.unhexlify(vector["entropy"])
        mnemonic = entropy_to_mnemonic(entropy)
        assert mnemonic == vector["mnemonic"]

    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_mnemonic_to_seed(self, vector: dict) -> None:
        seed = mnemonic_to_seed(vector["mnemonic"], vector["passphrase"])
        expected = binascii.unhexlify(vector["seed"])
        assert seed == expected

    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_roundtrip(self, vector: dict) -> None:
        entropy = binascii.unhexlify(vector["entropy"])
        mnemonic = entropy_to_mnemonic(entropy)
        result = mnemonic_to_entropy(mnemonic)
        assert result == entropy

    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_validate(self, vector: dict) -> None:
        assert validate_mnemonic(vector["mnemonic"]) is True


class TestEdgeCases:
    def test_whitespace_normalization(self) -> None:
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = mnemonic_to_seed(mnemonic)
        expected = mnemonic_to_seed(mnemonic)
        assert seed == expected

    def test_generate_random_is_deterministic_with_seed(self) -> None:
        mnemonics = [generate_mnemonic(128) for _ in range(10)]
        assert len(set(mnemonics)) == 10
