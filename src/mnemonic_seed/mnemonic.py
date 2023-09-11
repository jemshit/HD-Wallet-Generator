# MIT License
#
# Copyright (c) 2013 Pavol Rusnak
# Copyright (c) 2017 mruddy
# Copyright (c) 2022 Jemshit Iskenderov
#

import hashlib
import itertools
import os
import secrets
from typing import List, Union, Dict

from src.common.cryptography import hmac_sha512, sha256
from src.common.network import VERSION_BYTES, Network
from src.common.util import binary_search, normalize_string, base58_encode_with_checksum


class Mnemonic(object):
    """
    Source Libs:
    - https://github.com/trezor/python-mnemonic
    - https://github.com/ethereum/eth-account (more readable version of 'python-mnemonic')
    \n
    Sites:
    - https://iancoleman.io/bip39/ (use to confirm [words-seed] pair)
    \n
    Specs:
    - https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    \n
    Blogs:
    - https://wolovim.medium.com/ethereum-201-mnemonics-bb01a9108c38
    - https://academy.horizen.io/technology/expert/generating-keys-and-addresses/
    - https://cypherpunks-core.github.io/ethereumbook/05wallets.html
    """

    cached_wordlists: Dict[str, List[str]] = dict()
    """ 
    Static variable, shared by all instances of :class:`Mnemonic` class.\n
    :class:`Mnemonic` object is also created implicitly inside **Mnemonic.detect_language** method
    """
    cached_language_list: List[str] = list()
    """
    Used by **Mnemonic.get_languages** to cache the response
    """
    __valid_languages: set[str] = {"chinese simplified", "chinese_simplified", "chinese traditional",
                                   "chinese_traditional", "english", "french", "italian", "japanese",
                                   "korean", "spanish"}

    def __init__(self, language: str = "english"):
        """
        :param language: Possible values: **chinese simplified**, **chinese traditional**, **english**, **french**,
                        **italian**, **japanese**, **korean**, **spanish**
        """
        self.language: str = language.lower().replace(' ', '_')
        if self.language not in Mnemonic.__valid_languages:
            raise Exception("language argument is not valid. Must be one of these:"
                            "chinese simplified, chinese traditional, english, french, "
                            "italian, japanese, korean, spanish")
        self.word_count: int = 2048
        self.wordlist: List[str] = self.get_wordlist()

    def get_wordlist(self) \
            -> List[str]:
        """
        :returns: 2048 words of specified language
        """
        if self.language in Mnemonic.cached_wordlists.keys():
            return Mnemonic.cached_wordlists[self.language]

        # load file. Content must be SORTED for english for binary search!
        file_path = os.path.join(os.path.dirname(__file__), f"wordlist/{self.language}.txt")
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                wordlist = [word.strip() for word in file.readlines()]

            if len(wordlist) != self.word_count:
                raise Exception(f"Wordlist should contain {self.word_count} words, "
                                f"but it's {len(wordlist)} words long instead.")
        else:
            raise Exception("Language (file) not detected")

        Mnemonic.cached_wordlists[self.language] = wordlist

        return wordlist

    @staticmethod
    def get_languages() \
            -> List[str]:
        """
        :returns: list of possible languages that you can use to construct :class:`Mnemonic` class
        """
        if Mnemonic.cached_language_list:
            return Mnemonic.cached_language_list

        Mnemonic.cached_language_list = [
            file.split(".")[0]
            for file in os.listdir(os.path.join(os.path.dirname(__file__), "wordlist"))
            if file.endswith(".txt")
        ]

        return Mnemonic.cached_language_list

    @staticmethod
    def detect_language(raw_mnemonic) \
            -> str:
        """
        If matches to both chinese simplified and chinese traditional, chinese simplified is returned

        :param raw_mnemonic: list of words separated by space
        :returns: language
        :raises Exception: if no match or matches more than single language
        """
        mnemonic = normalize_string(raw_mnemonic)

        words = set(mnemonic.split(" "))
        matching_languages = {
            language
            for language in Mnemonic.get_languages()
            if len(words.intersection(Mnemonic(language).wordlist)) == len(words)
        }

        # No language had all words match it, so the language can't be fully determined
        if len(matching_languages) < 1:
            raise Exception(f"Language not detected for word(s): {raw_mnemonic}")

        # If both chinese simplified and chinese traditional match (because one is a subset of the
        # other) then return simplified. This doesn't hold for other languages.
        if len(matching_languages) == 2 and all("chinese" in lang for lang in matching_languages):
            return "chinese_simplified"

        # Because certain wordlists share some similar words, if we detect multiple languages
        # that the provided mnemonic word(s) could be valid in, we have to throw
        if len(matching_languages) > 1:
            raise Exception(f"Word(s) are valid in multiple languages: {raw_mnemonic}")

        (language,) = matching_languages
        return language

    def generate(self, strength: int = 256) \
            -> str:
        """
        Entropy must be a multiple of 32 bits.

        :param strength: possible values are 128, 160, 192, 224, 256.
                        128->12 words, 256->24 words
        :returns: words
        :raises ValueError: if strength is not valid
        :raises Exception: if result mnemonic is somehow not valid
        """

        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Invalid strength value. Allowed values are [128, 160, 192, 224, 256].")

        return self.to_mnemonic(secrets.token_bytes(strength // 8))

    def to_mnemonic(self, entropy_bytes: bytes) \
            -> str:
        """
        :param entropy_bytes: possible length: 16, 20, 24, 28, 32
        :return: words
        :raises ValueError: if entropy_bytes is not valid
        :raises Exception: if result mnemonic is somehow not valid
        """
        if len(entropy_bytes) not in [16, 20, 24, 28, 32]:
            raise ValueError(f"Data length should be one of the following: [16, 20, 24, 28, 32], "
                             f"but it is not {len(entropy_bytes)}.")

        entropy_bin: bin = bin(int.from_bytes(entropy_bytes, byteorder="big"))[2:].zfill(len(entropy_bytes) * 8)
        entropy_hash: str = sha256(entropy_bytes).hex()
        entropy_hash_padded: bin = bin(int(entropy_hash, 16))[2:].zfill(256)
        # first entropy / 32 bits of its SHA256 hash
        checksum_size: int = len(entropy_bytes) * 8 // 32
        checksum: bin = entropy_hash_padded[:checksum_size]

        # 256 + 8 = 264 bit (or 128 + 4 = 132 bit)
        entropy_with_checksum: bin = entropy_bin + checksum

        # take concatenated bits and split them into groups of 11 bits. Each group encodes number from 0-2047.
        # convert numbers into words
        words = []
        for word_counter in range(len(entropy_with_checksum) // 11):
            word_index = int(entropy_with_checksum[word_counter * 11: (word_counter + 1) * 11], 2)
            words.append(self.wordlist[word_index])

        # Japanese must be joined by ideographic space
        if self.language == "japanese":
            result = "\u3000".join(words)
        else:
            result = " ".join(words)

        if not self.is_mnemonic_valid(result):
            raise Exception("Result mnemonic is somehow invalid!")

        return result

    def is_mnemonic_valid(self, mnemonic: str) \
            -> bool:
        """
        You can't use random 12-24 words, checksum will fail.\n
        It must have been generated using algorithm.

        :param mnemonic: words, in length of 12, 15, 18, 21, 24
        """

        words: List[str] = normalize_string(mnemonic).split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            return False

        # calculate indices of words
        try:
            indices: List[str] = list(
                map(
                    lambda x: bin(self.wordlist.index(x))[2:].zfill(11),
                    words
                )
            )
            # string contains binary values
            entropy_with_checksum: str = "".join(indices)
        except ValueError:
            return False

        total_length: int = len(entropy_with_checksum)
        checksum_size: int = total_length // 33
        entropy_size = checksum_size * 32  # 4 * num_words // 3
        stored_entropy: str = entropy_with_checksum[:entropy_size]
        stored_checksum: str = entropy_with_checksum[-checksum_size:]

        entropy_bytes: bytes = int(stored_entropy, 2).to_bytes(total_length // 33 * 4, byteorder="big")
        entropy_hash: str = sha256(entropy_bytes).hex()
        entropy_hash_padded: bin = bin(int(entropy_hash, 16))[2:].zfill(256)
        computed_checksum: bin = entropy_hash_padded[:checksum_size]

        return stored_checksum == computed_checksum

    @staticmethod
    def to_seed(mnemonic: str,
                passphrase: str = "") \
            -> bytes:
        """
        :returns: 64 bytes seed used to generate "hd master key"
        """

        PBKDF2_ROUNDS = 2048

        mnemonic = normalize_string(mnemonic)
        passphrase = normalize_string(passphrase)
        # this domain separator ("mnemonic") is added per BIP39 spec to the passphrase
        # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
        passphrase = "mnemonic" + passphrase

        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        # uses key stretching function 'PBKDF2 using HMAC-SHA512', 2048 rounds
        stretched = hashlib.pbkdf2_hmac(
            "sha512",
            mnemonic_bytes,
            passphrase_bytes,
            PBKDF2_ROUNDS
        )
        return stretched[:64]

    def expand_word(self, prefix: str) \
            -> str:
        """
        Expands input prefix to full word, only if single target word is found in wordlist.
        Returns input itself if it can't expand.\n
        E.g: acce -> access
        """

        if prefix in self.wordlist:
            return prefix

        matches = [word for word in self.wordlist if word.startswith(prefix)]
        if len(matches) == 1:
            # matched exactly one word in the wordlist
            return matches[0]
        else:
            # exact match not found, return the input
            return prefix

    def expand(self, mnemonic: str) \
            -> str:
        """
        Expand each unfinished word in mnemonic to full word, if possible.\n
        E.g: "access acce acb acc act acti" -> "access access acb acc act action"
        """

        return " ".join(map(self.expand_word, mnemonic.split(" ")))

    def to_entropy(self, words: Union[List[str], str]) \
            -> bytes:
        """
        Convert wordlist to original entropy value.\n
        Source: https://github.com/bitcoinj/bitcoinj/blob/110da9691195f47b376872f95d81476e10b0e902/core/src/main/java/org/bitcoinj/crypto/MnemonicCode.java#L52

        :raises ValueError: if length of words is not valid or failed checksum
        :raises LookupError: if word is not found in wordlist
        """

        if not isinstance(words, list):
            words = words.split(" ")

        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                "Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d)." % len(words)
            )

        # construct the original entropy + checksum
        total_bits = len(words) * 11
        original_bits = [False] * total_bits
        word_counter = 0
        if self.language == "english":
            use_binary_search = True
        else:
            use_binary_search = False

        for word in words:
            if use_binary_search:
                word_index = binary_search(self.wordlist, word)
            else:
                word_index = self.wordlist.index(word)

            if word_index < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)

            # update original_bits according to word_index
            for index_bit in range(11):
                original_bits[(word_counter * 11) + index_bit] = (word_index & (1 << (10 - index_bit))) != 0

            word_counter += 1

        checksum_bits = total_bits // 33
        entropy_bits = total_bits - checksum_bits

        # extract original entropy as bytes
        entropy = bytearray(entropy_bits // 8)
        for entropy_bit_index in range(len(entropy)):
            for bit_index in range(8):
                if original_bits[(entropy_bit_index * 8) + bit_index]:
                    entropy[entropy_bit_index] |= 1 << (7 - bit_index)

        # take the digest of the entropy.
        entropy_hash_computed = sha256(entropy)
        checksum_bits_computed = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in entropy_hash_computed
            )
        )

        # check all the checksum bits
        for checksum_bit_index in range(checksum_bits):
            if original_bits[entropy_bits + checksum_bit_index] != checksum_bits_computed[checksum_bit_index]:
                raise ValueError("Failed checksum.")

        return bytes(entropy)

    @staticmethod
    def to_master_xprv(seed: bytes,
                       network: Network) \
            -> str:
        """
        a.k.a. Root Key. Only for master node

        :raises ValueError: if length of seed is not 64
        """

        if len(seed) != 64:
            raise ValueError("Provided seed should have length of 64")

        seed_hashed: bytes = hmac_sha512(key=b"Bitcoin seed",
                                         data=seed)

        # <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format>
        version_bytes: bytes = VERSION_BYTES[network]
        depth: bytes = b"\x00"
        parents_fingerprint: bytes = b'\x00' * 4
        child_index: bytes = b'\x00' * 4
        master_sk: bytes = seed_hashed[:32]
        master_cc: bytes = seed_hashed[32:]

        # 78 byte
        xprv_wo_checksum = (
                version_bytes +  # 4 bytes
                depth +  # 1 byte
                parents_fingerprint +  # 4 bytes
                child_index +  # 4 bytes
                master_cc +  # 32 bytes
                b"\x00" + master_sk  # 33 bytes
        )

        # double hash using SHA256
        # xprv_hashed = sha256_double(xprv_wo_checksum)
        # append 4 bytes of checksum
        # checksum = xprv_hashed[:4]
        # xprv_with_checksum = xprv_wo_checksum + checksum

        # return base58 after appending checksum
        return base58_encode_with_checksum(xprv_wo_checksum)
