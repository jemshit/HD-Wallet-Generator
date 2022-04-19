# MIT License
#
# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2022 Jemshit Iskenderov
#

from dataclasses import dataclass
from typing import Union, Optional, List, Tuple

from .ecc_key import ECPubKey, ECPrvKey, CURVE_ORDER
from ..common.cryptography import hmac_sha512, ripemd160_hashed, keccak_256
from ..common.network import Network, get_network_from_bytes, get_private_version_byte_of, \
    get_public_version_byte_of
from ..common.util import base58_decode_with_checksum, base58_encode_with_checksum, address_with_checksum, \
    HARDENED_INDEX, UINT32_MAX, parse_path_as_uint32

"""
Libs:
- https://github.com/spesmilo/electrum (mainly copied from here, code not readable)
- https://github.com/ethereum/py-hdwallet (second ref code. uses pure python version (not secure) of libsecp256k1)
- https://github.com/trezor/python-mnemonic (only master (depth=0) xprv)
- https://github.com/ethereum/eth-account (supports "parent sk -> child sk" only)
- https://github.com/bitcoin/bitcoin src/secp256k1/src/secp256k1.c (c code of libsecp256k1, to understand methods used)
- https://github.com/ethereum/eth-keys/ (to sign, verify, no key derivation. Can be used to test validity of keys generated)
- https://github.com/bitcoinj/bitcoinj (java implementation) /HDKeyDerivation.java
- https://github.com/darosior/python-bip32 (not used, but it is readable)

Specs:
- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

Blogs:
- https://wolovim.medium.com/ethereum-201-hd-wallets-11d0c93c87f7
- https://bitcoin.stackexchange.com/a/63996/66808
- https://academy.horizen.io/technology/expert/wallets-expert/ (it has errors on child key derivation algorithm)
- https://cypherpunks-core.github.io/ethereumbook/05wallets.html (no code)

Abbreviations:
- key = private | public
- xkey = xprv | xpub (key+chain_code+depth+..)
- ECC = Elliptic Curve Cryptography
- wo = without
- account extended keys = xkeys of account level/depth in bip-44 path
- p2pkh = pay to public key hash. alternatives are segwit address etc..

"""


@dataclass
class BIP32Node:
    """
    - Hosts 'xprv'+'xpub' or 'xpub'. Extended key parts (network, ec_key, chain_code, depth, parent_fingerprint, child_index) are stored separately
    - privateKey, publicKey is stored in 'ec_key' field
    - 'xprv' node can be converted to 'xpub' node. Or 'xpub' can be generated from 'xprv' without converting
    - There are no pointers to parent or children nodes
    """

    # 4 byte
    network: Network
    # 33 byte; not extended key, just regular prv|pub
    ec_key: Union[ECPubKey, ECPrvKey]
    # 32 byte
    chain_code: bytes
    # 1 byte (= 2 digit hex: [0-255]); m -> depth=0; m/44'/60'/0/0 -> depth=0/1/2/3/4
    depth: int = 0
    # 4 byte
    parent_fingerprint: bytes = b'\x00' * 4
    # 4 byte
    child_index: bytes = b'\x00' * 4
    # 4 byte, this node's fingerprint
    _fingerprint: Optional[bytes] = None

    @staticmethod
    def from_root_seed(seed: bytes,
                       network: Network,
                       check_seed_len: bool = True) \
            -> 'BIP32Node':
        """
        :param check_seed_len: if HD wallet, it must be 64 bytes. Otherwise, it can be in less size
        """

        if check_seed_len and len(seed) != 64:
            raise Exception(f"Seed length is not 64: {len(seed)}")

        # 512 bit = 64 byte
        hashed_seed: bytes = hmac_sha512(key=b"Bitcoin seed",
                                         data=seed)
        # master private key
        master_sk: bytes = hashed_seed[:32]
        # master chain code
        master_cc: bytes = hashed_seed[32:]

        return BIP32Node(network=network,
                         ec_key=ECPrvKey(master_sk),
                         chain_code=master_cc,
                         depth=0,
                         parent_fingerprint=b'\x00' * 4,
                         child_index=b'\x00' * 4)

    @staticmethod
    def from_any_xkey(xkey: str) \
            -> 'BIP32Node':
        """
        :param xkey: either 'xprv' or 'xpub'. network, depth, child_index etc... can be extracted from this
        """

        xkey_wo_checksum: bytes = base58_decode_with_checksum(xkey)
        if len(xkey_wo_checksum) != 78:
            raise Exception(f'Invalid length for extended key: {len(xkey_wo_checksum)}')

        # extract parts
        version_bytes: bytes = xkey_wo_checksum[:4]
        depth: int = xkey_wo_checksum[4]
        parents_fingerprint: bytes = xkey_wo_checksum[5:9]
        child_index: bytes = xkey_wo_checksum[9:13]
        chain_code: bytes = xkey_wo_checksum[13:13 + 32]

        # sanity check
        if depth == 0:
            if parents_fingerprint != b'\x00' * 4:
                raise Exception("Fingerprint must be 0 if depth is 0")
            if child_index != b'\x00' * 4:
                raise Exception("Child index must be 0 if depth is 0")
        if parents_fingerprint == b'\x00' * 4:
            if depth != 0:
                raise Exception("Depth must be 0 if parent fingerprint is 0")

        network = get_network_from_bytes(version_bytes)
        if network.is_private():
            # sanity check
            prv_key_prefix: int = xkey_wo_checksum[13 + 32]
            if prv_key_prefix != 0:
                raise Exception(f"Invalid private key prefix: {prv_key_prefix}")

            # ignore 1 byte prefix
            ec_key = ECPrvKey(xkey_wo_checksum[13 + 33:])
        else:
            ec_key = ECPubKey(xkey_wo_checksum[13 + 32:])

        return BIP32Node(network=network,
                         ec_key=ec_key,
                         chain_code=chain_code,
                         depth=depth,
                         parent_fingerprint=parents_fingerprint,
                         child_index=child_index)

    def is_private(self) \
            -> bool:
        if self.network.is_private() and not isinstance(self.ec_key, ECPrvKey):
            raise Exception("Inconsistency between 'network' & 'ec_key' type")
        if self.network.is_public() and not isinstance(self.ec_key, ECPubKey):
            raise Exception("Inconsistency between 'network' & 'ec_key' type")

        return self.network.is_private()

    def get_self_fingerprint(self) \
            -> bytes:
        """
        :return: This node's fingerprint, not parent's!
        """

        if not self._fingerprint:
            pub_key: bytes = self.ec_key.get_pubkey(compressed=True)
            pub_key_hashed: bytes = ripemd160_hashed(pub_key)
            self._fingerprint = pub_key_hashed[0:4]

        return self._fingerprint

    def get_child_index_as_str(self) \
            -> str:
        child_index: int = int.from_bytes(self.child_index, byteorder='big', signed=False)
        if child_index < HARDENED_INDEX:
            # non-hardened
            return str(child_index)
        else:
            # hardened
            index = child_index - HARDENED_INDEX
            return str(index) + "'"

    def get_xprv(self) \
            -> str:
        """
        Only if this is private node
        """

        if not self.is_private():
            raise Exception("This Node hosts only Extended PublicKey")

        xprv_wo_checksum: bytes = BIP32Node.build_xkey_wo_checksum(
            version_bytes=get_private_version_byte_of(self.network),
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_index=self.child_index,
            chain_code=self.chain_code,
            key=bytes([0]) + self.ec_key.get_prv_key()
        )

        return base58_encode_with_checksum(xprv_wo_checksum)

    def get_xpub(self) \
            -> str:
        xpub_wo_checksum: bytes = BIP32Node.build_xkey_wo_checksum(
            version_bytes=get_public_version_byte_of(self.network),
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_index=self.child_index,
            chain_code=self.chain_code,
            key=self.ec_key.get_pubkey(compressed=True)
        )

        return base58_encode_with_checksum(xpub_wo_checksum)

    @staticmethod
    def build_xkey_wo_checksum(version_bytes: bytes,
                               depth: int,
                               parent_fingerprint: bytes,
                               child_index: bytes,
                               chain_code: bytes,
                               key: bytes) \
            -> bytes:
        """
        Use this to not mis-align parts while merging. Specify parameter names explicitly when calling
        :return: 78 byte
        """

        xkey_wo_checksum = (version_bytes +
                            bytes([depth]) +
                            parent_fingerprint +
                            child_index +
                            chain_code +
                            key)
        if len(xkey_wo_checksum) != 78:
            raise Exception(f'Invalid length for extended key: {len(xkey_wo_checksum)}')

        return xkey_wo_checksum

    def convert_to_public(self) \
            -> 'BIP32Node':
        """
        :return: new BIP32Node that hosts 'xpub', only if child_index is not hardened
        """

        if not self.is_private():
            return self
        is_hardened = int.from_bytes(self.child_index, byteorder='big', signed=False) >= HARDENED_INDEX
        if is_hardened:
            raise Exception("This node is hardened. It can't be converted to public node, "
                            "otherwise pub node will have hardened child index (inconsistent)")

        ec_pub: ECPubKey = self.ec_key.convert_to_public()

        return BIP32Node(network=self.network.invert(),
                         ec_key=ec_pub,
                         chain_code=self.chain_code,
                         depth=self.depth,
                         parent_fingerprint=self.parent_fingerprint,
                         child_index=self.child_index)

    def get_p2pkh_address(self) \
            -> str:
        """
        :return: 21 byte (42 in hex) address with leading 0x. EIP-55 checksum encoded into capitalization
        """

        # 65 byte
        pub_key_with_header: bytes = self.ec_key.get_pubkey(compressed=False)
        # 64 byte
        pub_key_wo_header: bytes = pub_key_with_header[1:]
        if len(pub_key_wo_header) != 64:
            raise Exception(f"pub_key_wo_header len must be 64: {len(pub_key_wo_header)}")

        # 256 bit, 32 byte
        digest: bytes = keccak_256(pub_key_wo_header)
        if len(digest) != 32:
            raise Exception(f"digest len must be 32:{len(digest)}")

        # 21 byte (42 in hex)
        address: str = '0x' + digest[-20:].hex()
        return address_with_checksum(address)

    def child_xprv_node(self, path: str) \
            -> 'BIP32Node':
        """
        - Computes a child extended private key (hardened or non-hardened) from the parent extended private key
        - If n is hardened, the resulting private key's corresponding public key can NOT be determined
        without the parent privateKey.

        :param path: it is path after this node (relative path)

        :return: BIP32Node with ECPrvKey
        """

        if not path:
            raise Exception("derivation path must not be None")
        if not self.is_private():
            raise Exception("cannot do bip32 private derivation; private key missing")

        # path list can be empty if path is 'm'
        path: List[int] = parse_path_as_uint32(path)
        if len(path) == 0:
            if self.depth != 0:
                raise Exception("Path is 'm' but this is not master Node. Can't climb upwards.")
            else:
                # if it continues, parent_fingerprint will wrong (master's parent is fixed 0000)
                return self

        # parent's
        depth: int = self.depth
        chain_code: bytes = self.chain_code
        prv_key: bytes = self.ec_key.get_prv_key()

        last_parent_prv: bytes = prv_key
        last_child_index: int = int.from_bytes(self.child_index, byteorder='big', signed=False)
        for child_index in path:
            last_parent_prv = prv_key
            last_child_index = child_index
            # child's
            prv_key, chain_code = BIP32Node.child_prv(parent_prv=prv_key,
                                                      parent_cc=chain_code,
                                                      child_index=child_index)
            depth += 1

        parent_pub: bytes = ECPrvKey(last_parent_prv).get_pubkey(compressed=True)
        parent_pub_hashed: bytes = ripemd160_hashed(parent_pub)
        parent_fingerprint: bytes = parent_pub_hashed[0:4]

        return BIP32Node(network=self.network,
                         ec_key=ECPrvKey(prv_key),
                         chain_code=chain_code,
                         depth=depth,
                         parent_fingerprint=parent_fingerprint,
                         child_index=last_child_index.to_bytes(length=4, byteorder="big"))

    @staticmethod
    def child_prv(parent_prv: bytes,
                  parent_cc: bytes,
                  child_index: int) \
            -> Tuple[bytes, bytes]:
        """
        HSKD: Hardened Secret Key Derivation \n
        NSKD: Non-Hardened Secret Key Derivation \n

        Child private key derivation function (from parent private key)

        :return: child_prv, child_cc. child_prv is 32 byte
        """

        if len(parent_prv) != 32 or len(parent_cc) != 32:
            raise Exception(f"Invalid parent_prv({len(parent_prv)}) or parent_cc({len(parent_cc)}) len. Must be 32")

        if child_index < 0 or child_index > UINT32_MAX:
            raise ValueError('invalid child_index range')

        is_hardened = child_index >= HARDENED_INDEX

        if is_hardened:
            # HSKD: Hardened Secret Key Derivation
            # 33 byte + 4 byte(=32bit int)
            data: bytes = bytes([0]) + parent_prv + child_index.to_bytes(4, 'big')
        else:
            # NSKD: Non-Hardened Secret Key Derivation
            parent_pub: bytes = ECPrvKey(parent_prv).get_pubkey(compressed=True)
            # 33 byte (with header) + 4 byte(=32bit int)
            data: bytes = parent_pub + child_index.to_bytes(4, 'big')

        hashed: bytes = hmac_sha512(key=parent_cc,
                                    data=data)
        child_sk: bytes = hashed[:32]
        child_sk_int: int = int.from_bytes(child_sk, byteorder='big', signed=False)
        child_cc: bytes = hashed[32:]

        parent_prv_int = int.from_bytes(parent_prv, byteorder='big', signed=False)
        child_prv: int = (child_sk_int + parent_prv_int) % CURVE_ORDER
        if child_sk_int >= CURVE_ORDER or child_prv == 0:
            raise Exception("InvalidECPointException")
        child_prv: bytes = int.to_bytes(child_prv, length=32, byteorder='big', signed=False)

        return child_prv, child_cc

    def child_xpub_node(self, path: str) \
            -> 'BIP32Node':
        """
        Returns a child extended public key from the parent extended public key.
        It is only defined for non-hardened child keys.

        :param path: it is path after this node (relative path)

        :return: BIP32Node with ECPubKey
        """

        if not path:
            raise Exception("derivation path must not be None")

        # path list can be empty if path is 'm'
        path: List[int] = parse_path_as_uint32(path)
        if len(path) == 0:
            if self.depth != 0:
                raise Exception("Path is 'm' but this is not master Node. Can't climb upwards.")
            else:
                # if it continues, parent_fingerprint will wrong (master's parent is fixed 0000)
                return self

        # parent's
        depth: int = self.depth
        chain_code: bytes = self.chain_code
        pub_key: bytes = self.ec_key.get_pubkey(compressed=True)

        last_parent_pubkey = pub_key
        last_child_index = int.from_bytes(self.child_index, byteorder='big', signed=False)
        for child_index in path:
            last_parent_pubkey = pub_key
            last_child_index = child_index
            # child's
            pub_key, chain_code = BIP32Node.child_pub(parent_pub=pub_key,
                                                      parent_cc=chain_code,
                                                      child_index=child_index)
            depth += 1

        parent_pub_hashed: bytes = ripemd160_hashed(last_parent_pubkey)
        parent_fingerprint: bytes = parent_pub_hashed[0:4]
        return BIP32Node(network=self.network,
                         ec_key=ECPubKey(pub_key),
                         chain_code=chain_code,
                         depth=depth,
                         parent_fingerprint=parent_fingerprint,
                         child_index=last_child_index.to_bytes(length=4, byteorder="big"))

    @staticmethod
    def child_pub(parent_pub: bytes,
                  parent_cc: bytes,
                  child_index: int) \
            -> Tuple[bytes, bytes]:
        """
        NPKD: Non-Hardened Public Key Derivation \n

        Non-hardened Child public key derivation function (from parent public key only).

        :return: child_pub, child_cc. child_pub is compressed, 33 byte
        """

        if len(parent_pub) != 33 or len(parent_cc) != 32:
            raise Exception(
                f"Invalid parent_pub({len(parent_pub)}) or parent_cc({len(parent_cc)}) len. Must be 33 and 32")

        if child_index < 0 or child_index > UINT32_MAX:
            raise ValueError('invalid child_index range')

        is_hardened = child_index >= HARDENED_INDEX
        if is_hardened:
            raise Exception('not possible to derive hardened child from parent_pub')

        # NPKD: Non-Hardened Public Key Derivation
        # 33 byte (with header) + 4 byte(=32bit int)
        data: bytes = parent_pub + child_index.to_bytes(4, 'big')
        hashed: bytes = hmac_sha512(key=parent_cc,
                                    data=data)
        child_sk: bytes = hashed[:32]
        child_sk_int: int = int.from_bytes(child_sk, byteorder='big', signed=False)
        child_cc: bytes = hashed[32:]

        child_pub: ECPubKey = ECPrvKey(child_sk) + ECPubKey(parent_pub)
        if child_sk_int >= CURVE_ORDER or child_pub.is_at_infinity():
            raise Exception("InvalidECPointException")
        child_pub: bytes = child_pub.get_pubkey(compressed=True)

        return child_pub, child_cc
