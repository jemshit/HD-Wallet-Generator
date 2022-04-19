#
# Copyright (c) 2022 Jemshit Iskenderov
#

import bisect
import unicodedata
from typing import TypeVar, Sequence, Optional, AnyStr, List

from src.common.cryptography import keccak_256, sha256_double

"""
encode/decode allowed. It can use cryptography.py
"""

GENERIC_TYPE = TypeVar("GENERIC_TYPE")


def binary_search(items: Sequence[GENERIC_TYPE],
                  value: GENERIC_TYPE,
                  low: int = 0,
                  high: Optional[int] = None) \
        -> int:
    """
    Assumes "items" is sorted

    Source: <https://stackoverflow.com/questions/212358/binary-search-bisection-in-python/2233940#2233940>
    """

    if high is None:
        high = len(items)

    # find insertion position
    pos = bisect.bisect_left(items, value, low, high)

    if pos != high and items[pos] == value:
        return pos
    else:
        return -1


def normalize_string(txt: AnyStr) \
        -> str:
    if isinstance(txt, bytes):
        utxt = txt.decode("utf8")
    elif isinstance(txt, str):
        utxt = txt
    else:
        raise TypeError("String value expected")

    return unicodedata.normalize("NFKD", utxt)


# no "I,l,0,O" chars
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(text: bytes) \
        -> str:
    """
    Encode a string using Base58

    Source 1: <https://github.com/keis/base58>
    Source 2: <https://github.com/spesmilo/electrum/blob/master/electrum/bitcoin.py>. Fails on some tests
    Source 3: <https://github.com/trezor/python-mnemonic/blob/master/src/mnemonic/mnemonic.py>. Fails on some tests

    Test Online: https://appdevtools.com/base58-encoder-decoder
    """

    len_original = len(text)
    text = text.lstrip(b'\0')
    len_without_0s = len(text)

    power, sum_value = 1, 0
    for char in reversed(text):
        sum_value += power * char
        power = power << 8

    result = ""
    while sum_value:
        sum_value, mod = divmod(sum_value, 58)
        result = BASE58_ALPHABET[mod:mod + 1] + result

    # pad with 1
    pad_count = len_original - len_without_0s
    result = BASE58_ALPHABET[0] * pad_count + result

    return result


def base58_decode(text: str) \
        -> bytes:
    """
    Decode a string using Base58

    Source: <https://github.com/spesmilo/electrum/blob/master/electrum/bitcoin.py>

    Test Online: https://appdevtools.com/base58-encoder-decoder
    """

    power, sum_value = 1, 0
    for char in reversed(text):
        digit_index = BASE58_ALPHABET.find(char)
        if digit_index == -1:
            raise Exception('Forbidden character {} for base {}'.format(char, 58))

        sum_value += digit_index * power
        power *= 58

    result = bytearray()
    while sum_value >= 256:
        sum_value, mod = divmod(sum_value, 256)
        result.append(mod)
    if sum_value > 0:
        result.append(sum_value)

    # pad with 0
    pad_count = 0
    for char in text:
        if char == BASE58_ALPHABET[0]:
            pad_count += 1
        else:
            break
    result.extend(b'\x00' * pad_count)
    result.reverse()

    return bytes(result)


def base58_encode_with_checksum(extended_key: bytes) \
        -> str:
    extended_key_hash = sha256_double(extended_key)
    checksum = extended_key_hash[:4]
    return base58_encode(extended_key + checksum)


def base58_decode_with_checksum(extended_key_encoded: str) \
        -> bytes:
    extended_key_with_checksum = base58_decode(extended_key_encoded)
    extended_key = extended_key_with_checksum[0:-4]
    checksum_stored = extended_key_with_checksum[-4:]
    checksum_computed = sha256_double(extended_key)[:4]
    if checksum_computed != checksum_stored:
        raise Exception(f'Invalid checksum, calculated {checksum_computed.hex()}, found {checksum_stored.hex()}')
    else:
        return extended_key


# normal child: [0, 2^31-1]; hardened child: [2^31, 2^32-1]
HARDENED_INDEX = 2 ** 31  # 0x80000000 = 2147483648, 32 bit = 4 byte
UINT32_MAX = (1 << 32) - 1  # 2^32-1 = 4294967295, 32 bit = 4 byte


def parse_path_as_uint32(path: str) \
        -> List[int]:
    """
    Convert bip32 path to list of uint32 integers by appending hardened prefix
    m/0/1h/1' -> [0, 2**31+1, 2**31+1]

    :return: Valid list or empty list only if path is 'm'
    """

    if not path:
        raise Exception("Empty path")

    if path.endswith("/"):
        path: str = path[:-1]

    if path.startswith("/"):
        path: str = path[1:]

    contains_m = False
    if path[0] == "m":
        contains_m = True
        path: str = path[2:]

    if len(path) == 0:
        if contains_m:
            return []
        else:
            raise Exception("Empty and invalid path!")
    path: List[str] = path.split('/')

    result = []
    for part in path:
        # unknown prefix in part
        if not part[0].isnumeric():
            raise Exception(f"Unknown prefix in part {part}")

        # unknown postfix in part
        if not part.endswith("'") and not part.endswith("h"):
            if not part.isnumeric():
                raise Exception(f"Can't parse part {part}")

        # hardened
        prefix = 0
        if part.endswith("'") or part.endswith("h"):
            part = part[:-1]
            prefix = HARDENED_INDEX

        child_index = prefix + abs(int(part))
        if child_index > UINT32_MAX:
            raise ValueError(f"bip32 path child index too large: {child_index} > {UINT32_MAX}")

        result.append(child_index)

    if len(result) == 0:
        raise Exception(f"path {path} yielded empty int path list")

    return result


def parse_path_as_str(path: Sequence[int]) \
        -> str:
    result = "m/"
    for part in path:
        if not isinstance(part, int):
            raise TypeError(f"bip32 path child index must be int: {part}")
        if not (0 <= part <= UINT32_MAX):
            raise ValueError(f"bip32 path child index out of range: {part}")

        prime = ""
        if part >= HARDENED_INDEX:
            prime = "'"
            part = part - HARDENED_INDEX
        result += str(part) + prime + '/'
    # cut trailing "/"
    result = result[:-1]

    return result


def address_with_checksum(address: str) \
        -> str:
    """
    Checksum is not appended as in bitcoin, but rather is encoded into capitalization of hex letters, backward compatible

    <https://cypherpunks-core.github.io/ethereumbook/04keys-addresses.html>
    <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md>
    <https://github.com/meherett/python-hdwallet>

    :param address: 21 byte (42 in hex) with leading 0x or 20 byte (40 in hex) without it
    :return: 21 (42 in hex) byte address with leading 0x
    """

    address: str = address.lower()
    if len(address) == 42:
        if address[:2] == '0x':
            address = address[2:]
        else:
            raise Exception("Unknown address prefix")

    if len(address) != 40:
        raise Exception(f"Invalid address len, must be 40:{len(address)}")

    address_hashed: str = keccak_256(address.encode("ascii")).hex()

    result = ""
    for index, char in enumerate(address):
        if int(address_hashed[index], 16) >= 8:
            result += char.upper()
        else:
            result += char

    if len(result) != 40:
        raise Exception(f"Invalid result len, must be 40:{len(address)}")
    return "0x" + result
