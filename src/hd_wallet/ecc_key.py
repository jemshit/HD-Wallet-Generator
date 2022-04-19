# MIT License
#
# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2022 Jemshit Iskenderov
#

import ctypes
import functools
from ctypes import (byref, c_size_t, create_string_buffer, cast, c_char_p)
from typing import Tuple, Optional

import coincurve

from .secp256k1 import _libsecp256k1, SECP256K1_EC_UNCOMPRESSED


# for extra check (uses coincurve, we don't use it anywhere else)
def is_prv_key_valid(prv_key: bytes) \
        -> bool:
    try:
        coincurve.PrivateKey(prv_key)
        return True
    except ValueError:
        return False


# for extra check (uses coincurve, we don't use it anywhere else)
def is_pub_key_valid(pub_key: bytes) \
        -> bool:
    try:
        coincurve.PublicKey(pub_key)
        return True
    except ValueError:
        return False


"""
Based on the elliptic curve secp256k1 used by ethereum, in order for the 256-bit private key to be valid,
it must be smaller than the curve's parameter n which is as below
<https://ethereum.stackexchange.com/a/74128/96467>
<https://crypto.stackexchange.com/a/72739/101128>
"""
CURVE_ORDER: int = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141


@functools.total_ordering
class ECPubKey(object):
    """
    PubKey is basically x+y point (uncompressed)
    """

    def __init__(self, pub_key: Optional[bytes]):
        """
        :param pub_key: Accepts both compressed and uncompressed pub_key
        """

        if pub_key is not None:
            if len(pub_key) != 33 and len(pub_key) != 65:
                raise Exception("Invalid pub_key length, must be 33 or 65")
            # sanity check
            if len(pub_key) == 33:
                if pub_key[0] != 3 and pub_key[0] != 2:
                    raise Exception(f"Invalid compressed public key header: {pub_key[0]}")
            elif len(pub_key) == 65:
                if pub_key[0] != 4:
                    raise Exception(f"Invalid uncompressed public key header: {pub_key[0]}")

            self._x, self._y = ECPubKey.x_and_y_from_pubkey(pub_key)

            # this is extra check, so call it lastly
            if not is_pub_key_valid(pub_key):
                raise Exception('Invalid pub_key')

        else:
            # Point at INFINITY
            self._x, self._y = None, None

    @staticmethod
    def x_and_y_from_pubkey(pub_key: bytes) \
            -> Tuple[int, int]:
        pubkey_ptr: ctypes.Array = ECPubKey.to_libsecp256k1_pubkey_ptr(pub_key)
        pubkey_serialized: bytes = ECPubKey.from_libsecp256k1_pubkey_ptr(pubkey_ptr)

        # pubkey_serialized[0] = 0x04
        x: int = int.from_bytes(pubkey_serialized[1:33], byteorder='big', signed=False)
        y: int = int.from_bytes(pubkey_serialized[33:65], byteorder='big', signed=False)

        return x, y

    @staticmethod
    def from_x_and_y(x: int,
                     y: int) \
            -> 'ECPubKey':
        """
        :return: ECPubKey("header+x+y"), 65 bytes
        """

        _bytes = (b'\x04'
                  + int.to_bytes(x, length=32, byteorder='big', signed=False)
                  + int.to_bytes(y, length=32, byteorder='big', signed=False))
        return ECPubKey(_bytes)

    @staticmethod
    def to_libsecp256k1_pubkey_ptr(pub_key: bytes) \
            -> ctypes.Array:
        """
        :param pub_key: Can be both compressed (65 byte) and uncompressed (33 byte)

        :return: 64 byte, uncompressed
        """

        pubkey_ptr: ctypes.Array = create_string_buffer(64)
        # <https://github.com/bitcoin-core/secp256k1/blob/9a5a87e0f1276e0284446af1172056ea4693737f/src/eckey_impl.h#L17>
        success = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1.ctx,
            pubkey_ptr,
            pub_key,
            len(pub_key)
        )
        if not success:
            raise Exception('public key could not be parsed or is invalid')
        if len(pubkey_ptr) != 64:
            raise Exception(f'pubkey_ptr size is not 64: {len(pubkey_ptr)}')

        return pubkey_ptr

    @staticmethod
    def from_libsecp256k1_pubkey_ptr(pubkey_ptr: ctypes.Array) \
            -> bytes:
        """
        :param pubkey_ptr: 64 byte
        :return: 65 byte, uncompressed. header = result[0], x = result[1:33], y = result[33:65]
        """

        pubkey_serialized: ctypes.Array = create_string_buffer(65)
        pubkey_size: ctypes.c_size_t = c_size_t(65)
        success = _libsecp256k1.secp256k1_ec_pubkey_serialize(
            _libsecp256k1.ctx,
            pubkey_serialized,
            byref(pubkey_size),
            pubkey_ptr,
            SECP256K1_EC_UNCOMPRESSED
        )
        if not success:
            raise Exception("Not successful")
        if len(pubkey_serialized) != 65:
            raise Exception(f'pubkey_serialized size is not 65: {len(pubkey_serialized)}')

        pubkey_serialized: bytes = bytes(pubkey_serialized)
        if pubkey_serialized[0] != 0x04:
            # used SECP256K1_EC_UNCOMPRESSED above, so expect 0x04
            raise Exception("pubkey_serialized header is not 0x04")

        return pubkey_serialized

    def get_pubkey(self, compressed=True) \
            -> bytes:
        """
        Use compressed=True always for child key derivation functions

        :param compressed: to compress Y & -Y or not. Because they are identical values with different signs, it can be compressed

        :return: "header+x+y" 65 byte or "header+x" 33 byte
        """

        """
        BIP32 itself uses compressed:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#specification-key-derivation
        
        Electrum uses compressed public_key for HD wallet, except in '_to_libsecp256k1_pubkey_ptr' which actually
        doesn't care if input is compressed or not: 
        https://github.com/spesmilo/electrum/blob/250795f137281b8d2c8d29081949ee781a1c0b2a/electrum/bip32.py#L94
        https://github.com/spesmilo/electrum/blob/250795f137281b8d2c8d29081949ee781a1c0b2a/electrum/ecc.py#L237
        
        py-hdwallet always uses compressed public_key for HD wallet child node derivation:
        https://github.com/ethereum/py-hdwallet/blob/fc4b6b94cd5b5cf663087880f9c18090ec574474/hdwallet/utils.py#L94
        
        eth-keys doesn't generate HD Wallet, but it uses uncompressed public key for all operations (address, transaction, sign..)
        https://github.com/ethereum/eth-keys/blob/dd4f00a5d2f2b394665ccecc9817f753e58cc7bc/eth_keys/datatypes.py#L175
        
        EthereumBook writes "Ethereum only uses uncompressed public keys" (doesn't specify for address generation or hd-wallet generation):
        https://cypherpunks-core.github.io/ethereumbook/04keys-addresses.html
        
        PyCoin compresses for HD wallet:
        https://github.com/richardkiss/pycoin/blob/415a770768d1c4f490ec1d115c67436610c8c67f/pycoin/key/BIP32Node.py#L116
        
        BitcoinJ compresses for HD wallet:
        https://github.com/bitcoinj/bitcoinj/blob/6aa4e51de6004f7171802bbce9c1660228d05aae/core/src/main/java/org/bitcoinj/crypto/HDKeyDerivation.java#L158
        """

        if self.is_at_infinity():
            raise Exception('point is at infinity')

        # 32 byte each
        x: bytes = int.to_bytes(self._x, length=32, byteorder='big', signed=False)
        y: bytes = int.to_bytes(self._y, length=32, byteorder='big', signed=False)

        if compressed:
            is_y_odd = self._y & 1
            header: bytes = b'\x03' if is_y_odd else b'\x02'
            return header + x
        else:
            header: bytes = b'\x04'
            return header + x + y

    def point(self) \
            -> Tuple[int, int]:
        return self._x, self._y

    def is_at_infinity(self):
        return self._x is None \
               or self._x == 0 \
               or self._y is None \
               or self._y == 0

    def __repr__(self):
        if self.is_at_infinity():
            return f"<ECPubKey infinity>"

        return f"<ECPubKey {self.get_pubkey(compressed=False).hex()}>"

    def __hash__(self):
        return hash(self.point())

    def __eq__(self, other) \
            -> bool:
        # required for == POINT_AT_INFINITY

        if not isinstance(other, ECPubKey):
            return False

        return self.point() == other.point()

    def __add__(self, other) \
            -> 'ECPubKey':
        # required for ckd_pub

        if not isinstance(other, ECPubKey):
            raise TypeError(f'addition not defined for ECPubKey and {type(other)}')

        if self.is_at_infinity() or other.is_at_infinity():
            raise Exception("Someone is at infinity!")

        pubkey_ptr1: ctypes.Array = ECPubKey.to_libsecp256k1_pubkey_ptr(self.get_pubkey(compressed=True))
        pubkey_ptr2: ctypes.Array = ECPubKey.to_libsecp256k1_pubkey_ptr(other.get_pubkey(compressed=True))
        pubkey_sum_ptr: ctypes.Array = create_string_buffer(64)

        pubkey_ptr1: ctypes.c_char_p = cast(pubkey_ptr1, c_char_p)
        pubkey_ptr2: ctypes.c_char_p = cast(pubkey_ptr2, c_char_p)
        array_of_pubkey_ptrs = (c_char_p * 2)(pubkey_ptr1, pubkey_ptr2)
        success = _libsecp256k1.secp256k1_ec_pubkey_combine(_libsecp256k1.ctx,
                                                            pubkey_sum_ptr,
                                                            array_of_pubkey_ptrs,
                                                            2)
        if not success:
            raise Exception("Addition is not successful!")
            # return POINT_AT_INFINITY

        pub_key_combined: bytes = ECPubKey.from_libsecp256k1_pubkey_ptr(pubkey_sum_ptr)
        return ECPubKey(pub_key_combined)

    def __mul__(self, other: int) \
            -> 'ECPubKey':
        # required for ECPrvKey#init#GENERATOR * secret

        if not isinstance(other, int):
            raise TypeError(f'multiplication not defined for ECPubKey and {type(other)}')

        other %= CURVE_ORDER
        if self.is_at_infinity() or other == 0:
            raise Exception("Someone is at infinity")
            # return POINT_AT_INFINITY

        pubkey_ptr = ECPubKey.to_libsecp256k1_pubkey_ptr(self.get_pubkey(compressed=True))

        success = _libsecp256k1.secp256k1_ec_pubkey_tweak_mul(_libsecp256k1.ctx,
                                                              pubkey_ptr,
                                                              other.to_bytes(32, byteorder="big"))
        if not success:
            raise Exception("Multiplication is not successful!")
            # return POINT_AT_INFINITY

        pubkey_multiplied: bytes = ECPubKey.from_libsecp256k1_pubkey_ptr(pubkey_ptr)
        return ECPubKey(pubkey_multiplied)

    def __rmul__(self, other: int) \
            -> 'ECPubKey':
        # required for ECPrvKey#init.GENERATOR * secret
        return self * other

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        if not isinstance(other, ECPubKey):
            raise TypeError('comparison not defined for ECPubKey and {}'.format(type(other)))

        other_x = other.point()[0]
        return (self._x or 0) < (other_x or 0)


GENERATOR_POINT = ECPubKey(
    bytes.fromhex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'  # 0x04 + x
                  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')  # + y
)


class ECPrvKey(ECPubKey):
    """
    Each private key has corresponding public key. This class extends and creates ECPubKey in constructor
    """

    def __init__(self, prv_key: bytes):
        if len(prv_key) != 32:
            raise Exception('unexpected size for secret. should be 32 bytes, not {}'.format(len(prv_key)))

        prv_as_int: int = int.from_bytes(prv_key, byteorder='big', signed=False)
        if not self.is_key_within_curve_range(prv_as_int):
            raise Exception('Invalid prv_key (not within curve order)')
        # this is extra check, so call it lastly
        if not is_prv_key_valid(prv_key):
            raise Exception('Invalid prv_key')

        self.prv_key: int = prv_as_int

        # generate publicKey as well
        ec_pub: ECPubKey = GENERATOR_POINT * prv_as_int
        super().__init__(ec_pub.get_pubkey(compressed=True))

    @staticmethod
    def is_key_within_curve_range(prv_key: int) \
            -> bool:
        return 0 < prv_key < CURVE_ORDER

    def get_prv_key(self) \
            -> bytes:
        """
        :return: 32 byte
        """

        return int.to_bytes(self.prv_key, length=32, byteorder='big', signed=False)

    def convert_to_public(self) \
            -> 'ECPubKey':
        """
        :return: new ECPubKey
        """

        return ECPubKey(self.get_pubkey(compressed=True))

    def __repr__(self):
        return f"<ECPrvKey {self.get_prv_key().hex()}>"
