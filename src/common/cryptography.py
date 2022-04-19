# MIT License
#
# Copyright (C) 2018 The Electrum developers
# Copyright (c) 2022 Jemshit Iskenderov
#

import hashlib
import hmac

from eth_hash.auto import keccak

"""
No encode/decode, hashing and cryptography
"""


def sha256(data: bytes) \
        -> bytes:
    return hashlib.sha256(data).digest()


def sha256_double(data: bytes) \
        -> bytes:
    return sha256(sha256(data))


def hmac_sha512(*,
                key: bytes,
                data: bytes) \
        -> bytes:
    """
    node_sk = hashed_seed[:32]
    node_cc = hashed_seed[32:]

    :returns 64 byte = 512 bit
    """

    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, data, hashlib.sha512)
    else:
        return hmac.new(key, data, hashlib.sha512).digest()


def ripemd160_hashed(data: bytes) \
        -> bytes:
    data_hash = sha256(data)

    hash_function = hashlib.new('ripemd160')
    hash_function.update(data_hash)
    return hash_function.digest()


def keccak_256(data: bytes) \
        -> bytes:
    return keccak(data)
