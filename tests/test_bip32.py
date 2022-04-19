#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2012 <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors>
# Copyright (c) 2019 <https://github.com/ethereum/py-hdwallet>
# Copyright (c) 2021 <https://github.com/darosior/python-bip32>
# Copyright (c) 2022 <https://iancoleman.io/bip39/>
# Copyright (c) 2022 <http://bip32.org>
# Copyright (c) 2022 Jemshit Iskenderov
#

import json
import os
import unittest

from src.common.network import Network, VERSION_BYTES
from src.common.util import HARDENED_INDEX, UINT32_MAX, parse_path_as_str
from src.hd_wallet.bip32 import BIP32Node

"""
Implicitly tests ecc_key.py as well
"""


class BIP32Test(unittest.TestCase):
    _child_drv_file_path = os.path.join(os.path.dirname(__file__), 'child_derivation_vectors.json')

    def test_factory_methods(self):
        """
        This also test .get_xprv(), .get_xpub()
        """

        # korean, 24 words, eth
        seed = "0f2f8ca0052c915aee74df50680e31ab7e094141af0a61bca97fd46574de35735d5acd8b19fddd6ad6b981e8a18c78963e2ce2fbff8a53e10daf836290d57569"
        xprv_expected = "xprv9s21ZrQH143K28TiEqBVNVHeT4Hn9ND6YoV5SMFCjkskLHYtszB" \
                        "nEBXKviWxnxZCdTqJ9Qy8opUHyu2XL6wdbfPX6S1LN5BEkfAXB8bJMR1"
        xpub_expected = "xpub661MyMwAqRbcEcYBLriVjdEP168GYpvwv2QgEjepJ6QjD5t3R" \
                        "XW2myqomyDCyghPSStSALmeMSd7KCtj7CG5vb8BWEkU9fqj8eTPjYiE3QJ"
        cc_expected: bytes = bytes.fromhex("071b7e4faffb66f9d82b7044a2727b5312a6c0f65fae8be335c16abbab0a3513")
        pub_expected: bytes = bytes.fromhex("02c92d2c15c27c43c4229f86b79d3b1d4117f6a9fa3168b39f15fafb43cb9a6070")

        master_node = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)
        master_node2 = BIP32Node.from_any_xkey(xprv_expected)
        master_node3 = BIP32Node.from_any_xkey(xpub_expected)

        self.assertEqual(xprv_expected, master_node.get_xprv())
        self.assertEqual(xpub_expected, master_node.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node.child_index)
        self.assertEqual(0, master_node.depth)
        self.assertEqual(Network.MAIN_PRIVATE, master_node.network)
        self.assertEqual(pub_expected, master_node.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node.chain_code)

        self.assertEqual(xprv_expected, master_node2.get_xprv())
        self.assertEqual(xpub_expected, master_node2.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node2.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node2.child_index)
        self.assertEqual(0, master_node2.depth)
        self.assertEqual(Network.MAIN_PRIVATE, master_node2.network)
        self.assertEqual(pub_expected, master_node2.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node2.chain_code)

        with self.assertRaises(Exception):
            master_node3.get_xprv()
        self.assertEqual(xpub_expected, master_node3.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node3.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node3.child_index)
        self.assertEqual(0, master_node3.depth)
        self.assertEqual(Network.MAIN_PUBLIC, master_node3.network)
        self.assertEqual(pub_expected, master_node3.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node3.chain_code)

        # spanish, 24 words, eth
        seed = "5d4ab94ad65892110c63b0c5f49450c66e3640ec0b4313f8de0d57e49e85e69a730" \
               "f647597d16e4b6d6ab27d8bdc81e046cbddfac4d275233a3b2bfb4e80b713"
        xprv_expected = "xprv9s21ZrQH143K3wxr8Qye369piXMrCCc44LD22Qq6trM7jR7n" \
                        "pXWDujFRFaXPoRubGzd9b6b6P7jBoXScf6biQKBm4F8suaxfGcLgGSqzeKh"
        xpub_expected = "xpub661MyMwAqRbcGS3KESWeQE6ZGZCLbfKuRZ8cpoEiTBt6cDSwN4pUT" \
                        "XZu6t2HEm16H1tJzictESoT7vom2PLmVDzLPoZSViGqB7xFqHxvamz"
        cc_expected: bytes = bytes.fromhex("bdcfb2a5392eb971da047536649606fef5c6d16aac8b9174eac626c69f4ca886")
        pub_expected: bytes = bytes.fromhex("03c14b23cd13befce8a2d2dc98b2b5809a8d9025f21edbf74d460b2a565571c74c")

        master_node = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)
        master_node2 = BIP32Node.from_any_xkey(xprv_expected)
        master_node3 = BIP32Node.from_any_xkey(xpub_expected)

        self.assertEqual(xprv_expected, master_node.get_xprv())
        self.assertEqual(xpub_expected, master_node.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node.child_index)
        self.assertEqual(0, master_node.depth)
        self.assertEqual(Network.MAIN_PRIVATE, master_node.network)
        self.assertEqual(pub_expected, master_node.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node.chain_code)

        self.assertEqual(xprv_expected, master_node2.get_xprv())
        self.assertEqual(xpub_expected, master_node2.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node2.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node2.child_index)
        self.assertEqual(0, master_node2.depth)
        self.assertEqual(Network.MAIN_PRIVATE, master_node2.network)
        self.assertEqual(pub_expected, master_node2.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node2.chain_code)

        with self.assertRaises(Exception):
            master_node3.get_xprv()
        self.assertEqual(xpub_expected, master_node3.get_xpub())
        self.assertEqual(b'\x00' * 4, master_node3.parent_fingerprint)
        self.assertEqual(b'\x00' * 4, master_node3.child_index)
        self.assertEqual(0, master_node3.depth)
        self.assertEqual(Network.MAIN_PUBLIC, master_node3.network)
        self.assertEqual(pub_expected, master_node3.ec_key.get_pubkey())
        self.assertEqual(cc_expected, master_node3.chain_code)

    def test_factory_methods_invalid_inputs(self):
        # invalid seed len
        with self.assertRaises(Exception):
            BIP32Node.from_root_seed(bytes.fromhex("af62"), Network.MAIN_PRIVATE)

        #
        invalid_xpubs = [
            # pubkey version / prvkey mismatch (+ invalid public header)
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
            # invalid pubkey prefix 04
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
            # invalid pubkey prefix 01
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
            # zero depth with non-zero parent fingerprint
            "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
            # zero depth with non-zero index
            "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
            # unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
            # unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
            # invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY"
        ]
        for xpub in invalid_xpubs:
            with self.assertRaises(Exception):
                BIP32Node.from_any_xkey(xpub)

        invalid_xprvs = [
            # private key 0 not in 1..n-1
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
            # private key n not in 1..n-1
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
            # zero depth with non-zero index
            "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
            # invalid prvkey prefix 04
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
            # invalid prvkey prefix 01
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
            # zero depth with non-zero parent fingerprint
            "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
            # pubkey version / prvkey mismatch (invalid prefix)
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
            # unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
            # unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
            # invalid checksum
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL"
        ]
        for xprv in invalid_xprvs:
            with self.assertRaises(Exception):
                BIP32Node.from_any_xkey(xprv)

    def test_is_private(self):
        xprv_expected = "xprv9s21ZrQH143K28TiEqBVNVHeT4Hn9ND6YoV5SMFCjkskLHYtszB" \
                        "nEBXKviWxnxZCdTqJ9Qy8opUHyu2XL6wdbfPX6S1LN5BEkfAXB8bJMR1"
        xpub_expected = "xpub661MyMwAqRbcEcYBLriVjdEP168GYpvwv2QgEjepJ6QjD5t3R" \
                        "XW2myqomyDCyghPSStSALmeMSd7KCtj7CG5vb8BWEkU9fqj8eTPjYiE3QJ"

        master_node = BIP32Node.from_any_xkey(xprv_expected)
        master_node2 = BIP32Node.from_any_xkey(xpub_expected)

        self.assertTrue(master_node.is_private())
        self.assertFalse(master_node2.is_private())

    def test_child_index_str(self):
        seed = "0f2f8ca0052c915aee74df50680e31ab7e094141af0a61bca97fd46574de35735d5acd8b19fddd6ad6b981e8a18c78963e2ce2fbff8a53e10daf836290d57569"
        master_node = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)

        # last non-hardened
        child_path = "m/2147483647"
        child_prv_node = master_node.child_xprv_node(child_path)
        child_pub_node = master_node.child_xpub_node(child_path)
        child_index_expected = "2147483647"
        self.assertEqual(child_index_expected, child_prv_node.get_child_index_as_str())
        self.assertEqual(child_index_expected, child_pub_node.get_child_index_as_str())

        # first hardened
        child_path = "m/2147483648"
        child_prv_node = master_node.child_xprv_node(child_path)
        child_index_expected = "0'"
        self.assertEqual(child_index_expected, child_prv_node.get_child_index_as_str())

        # last hardened
        child_path = "m/4294967295"
        child_prv_node = master_node.child_xprv_node(child_path)
        child_index_expected = "2147483647'"
        self.assertEqual(child_index_expected, child_prv_node.get_child_index_as_str())

        # mixed
        child_path = "m/429496729/0'/12"
        child_prv_node = master_node.child_xprv_node(child_path)
        child_index_expected = "12"
        self.assertEqual(child_index_expected, child_prv_node.get_child_index_as_str())

        child_path = "m/429496729/0'/12'"
        child_prv_node = master_node.child_xprv_node(child_path)
        child_index_expected = "12'"
        self.assertEqual(child_index_expected, child_prv_node.get_child_index_as_str())

        # overflow
        child_path = "m/4294967296"
        with self.assertRaises(Exception):
            master_node.child_xprv_node(child_path)

    def test_build_xkey_wo_checksum(self):
        version_bytes = VERSION_BYTES[Network.TEST_PUBLIC]
        depth = 1
        parent_fingerprint = b'\x12\x34\x56\x78'
        child_index = b'\x11\x22\x33\x44'
        chain_code = bytes.fromhex("bdcfb2a5392eb971da047536649606fef5c6d16aac8b9174eac626c69f4ca886")
        key = bytes.fromhex("03c14b23cd13befce8a2d2dc98b2b5809a8d9025f21edbf74d460b2a565571c74c")
        expected = (
                version_bytes +
                depth.to_bytes(1, byteorder='big', signed=False) +
                parent_fingerprint +
                child_index +
                chain_code +
                key
        )
        actual = BIP32Node.build_xkey_wo_checksum(version_bytes,
                                                  depth,
                                                  parent_fingerprint,
                                                  child_index,
                                                  chain_code,
                                                  key)
        self.assertEqual(expected, actual)

        # invalid len
        with self.assertRaises(Exception):
            BIP32Node.build_xkey_wo_checksum(version_bytes,
                                             depth,
                                             parent_fingerprint,
                                             child_index,
                                             bytes.fromhex("dsfsf"),
                                             key)

    def test_convert_to_public(self):
        # m
        xprv_expected = "xprv9s21ZrQH143K28TiEqBVNVHeT4Hn9ND6YoV5SMFCjkskLHYtszB" \
                        "nEBXKviWxnxZCdTqJ9Qy8opUHyu2XL6wdbfPX6S1LN5BEkfAXB8bJMR1"
        xpub_expected = "xpub661MyMwAqRbcEcYBLriVjdEP168GYpvwv2QgEjepJ6QjD5t3R" \
                        "XW2myqomyDCyghPSStSALmeMSd7KCtj7CG5vb8BWEkU9fqj8eTPjYiE3QJ"

        master_prv = BIP32Node.from_any_xkey(xprv_expected)
        master_pub = master_prv.convert_to_public()

        self.assertEqual(master_prv.depth, master_pub.depth)
        self.assertEqual(master_prv.chain_code, master_pub.chain_code)
        self.assertEqual(master_prv.child_index, master_pub.child_index)
        self.assertEqual(master_prv.parent_fingerprint, master_pub.parent_fingerprint)
        self.assertEqual(master_prv.get_self_fingerprint(), master_pub.get_self_fingerprint())
        self.assertEqual(xpub_expected, master_prv.get_xpub())
        self.assertEqual(xpub_expected, master_pub.get_xpub())
        self.assertEqual(master_prv.ec_key.get_pubkey(), master_pub.ec_key.get_pubkey())

        # child
        child_prv = master_prv.child_xprv_node("/1'/0")
        child_pub = child_prv.convert_to_public()

        self.assertEqual(child_prv.depth, child_pub.depth)
        self.assertEqual(child_prv.chain_code, child_pub.chain_code)
        self.assertEqual(child_prv.child_index, child_pub.child_index)
        self.assertEqual(child_prv.parent_fingerprint, child_pub.parent_fingerprint)
        self.assertEqual(child_prv.get_self_fingerprint(), child_pub.get_self_fingerprint())
        self.assertEqual(child_prv.ec_key.get_pubkey(), child_pub.ec_key.get_pubkey())

        # public -> public
        child_pub2 = child_pub.convert_to_public()
        self.assertEqual(child_pub, child_pub2)

        # hardened node -> public (exception)
        child_prv = master_prv.child_xprv_node("/1'/0'")
        with self.assertRaises(Exception):
            child_prv.convert_to_public()

    def test_get_p2pkh_address(self):
        # chinese simpl, 21 words, eth
        seed = "c6d4e7fa14171f57f77263a5a85b487824af989dd0f8212cb14a11c0c6ca23c5f033ad31c250aeccbc2491f9f1ac052ed4d75ccfcedfdba34adf96c6fd966b9d"
        master = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)

        child = master.child_xprv_node("m/44'/60'/0'/0/0")
        self.assertEqual("0xaE369963Ea7E30c0d7f989BD304d23864e6bEb5d", child.get_p2pkh_address())
        child = master.child_xprv_node("m/44'/60'/0'/0/18")
        self.assertEqual("0x3BAA87c404014d414998159fBb979E928e17baF6", child.get_p2pkh_address())
        child = master.child_xprv_node("m/44'/60'/9'/0/3476/3487")
        self.assertEqual("0x57993cb33188b9671AD43Bb8ad9e2343A554A2c2", child.get_p2pkh_address())

    def test_child_derivation_vectors(self):
        with open(self._child_drv_file_path, "r") as file:
            vectors = json.load(file)
            # seed: '000102030405060708090a0b0c0d0e0f',
            # path: 'm',
            # xpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',  # noqa: E501
            # xprv: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',  # noqa: E501
            # depth : 0
            # child_index : "12'"

        for row in vectors:
            seed = row[0]
            path = row[1]
            xpub_expected = row[2]
            xprv_expected = row[3]
            depth_expected = row[4]
            child_index_expected = row[5]

            # create master node
            master_node = BIP32Node.from_root_seed(seed=bytes.fromhex(seed),
                                                   network=Network.MAIN_PRIVATE,
                                                   check_seed_len=False)

            # get the correct child private and public wallet nodes
            prv_child_node = master_node.child_xprv_node(path)

            # assert calculated values are correct
            self.assertEqual(xprv_expected, prv_child_node.get_xprv())
            self.assertEqual(xpub_expected, prv_child_node.get_xpub())
            self.assertEqual(depth_expected, prv_child_node.depth)
            self.assertEqual(child_index_expected, prv_child_node.get_child_index_as_str())

    def test_child_derivation_invalid_inputs(self):
        seed = "0f2f8ca0052c915aee74df50680e31ab7e094141af0a61bca97fd46574de35735d5acd8b19fddd6ad6b981e8a18c78963e2ce2fbff8a53e10daf836290d57569"

        # empty path
        master_node = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)
        with self.assertRaises(Exception):
            master_node.child_xprv_node("")
        with self.assertRaises(Exception):
            master_node.child_xpub_node("")

        # xprv child from xpub parent
        with self.assertRaises(Exception):
            parent = BIP32Node.from_any_xkey("xpub661MyMwAqRbcEcYBLriVjdEP168GYpvwv2Q"
                                             "gEjepJ6QjD5t3RXW2myqomyDCyghPSStSALmeMSd7KCtj7CG5vb8BWEkU9fqj8eTPjYiE3QJ")
            parent.child_xprv_node("m/3")

        # path is m but node is child
        with self.assertRaises(Exception):
            parent = BIP32Node.from_any_xkey(
                "xpub6BCvgoEKnVkEqwBYSLexFBxykmWE8fM6wuuWHD9127hGmPifmvD25cNhGmf6FcdrnDMMeDifgYuzT6r4229mWyh4L9QpoSdiS9iDQDStUBV")
            parent.child_xprv_node("m")
        with self.assertRaises(Exception):
            parent = BIP32Node.from_any_xkey(
                "xpub6BCvgoEKnVkEqwBYSLexFBxykmWE8fM6wuuWHD9127hGmPifmvD25cNhGmf6FcdrnDMMeDifgYuzT6r4229mWyh4L9QpoSdiS9iDQDStUBV")
            parent.child_xpub_node("m")

        # path is m and node is child, no exception
        master = BIP32Node.from_root_seed(bytes.fromhex(seed), Network.MAIN_PRIVATE)
        master.child_xprv_node("m")
        master.child_xpub_node("m")

        # static methods
        # valid len
        BIP32Node.child_prv(b'\x01' * 32, b'\x01' * 32, child_index=1)
        BIP32Node.child_pub(bytes.fromhex("02c92d2c15c27c43c4229f86b79d3b1d4117f6a9fa3168b39f15fafb43cb9a6070"),
                            b'\x01' * 32,
                            child_index=1)

        # invalid len
        with self.assertRaises(Exception):
            BIP32Node.child_prv(b'\x01' * 32, b'\x01', child_index=1)
        with self.assertRaises(Exception):
            BIP32Node.child_prv(b'\x01', b'\x01' * 32, child_index=1)
        with self.assertRaises(Exception):
            BIP32Node.child_pub(bytes.fromhex("02c92d2c15c27c43c4229f86b79d3b1d4117f6a9fa3168b39f15fafb43cb9a6070"),
                                b'\x01',
                                child_index=1)
        with self.assertRaises(Exception):
            BIP32Node.child_pub(b'\x01', b'\x01' * 32, child_index=1)

        # invalid child index
        with self.assertRaises(Exception):
            BIP32Node.child_prv(b'\x01' * 32, b'\x01' * 32, child_index=-1)
        with self.assertRaises(Exception):
            BIP32Node.child_pub(bytes.fromhex("02c92d2c15c27c43c4229f86b79d3b1d4117f6a9fa3168b39f15fafb43cb9a6070"),
                                b'\x01' * 32,
                                child_index=-1)
        with self.assertRaises(Exception):
            BIP32Node.child_prv(b'\x01' * 32, b'\x01' * 32, child_index=UINT32_MAX + 1)
        with self.assertRaises(Exception):
            BIP32Node.child_pub(bytes.fromhex("02c92d2c15c27c43c4229f86b79d3b1d4117f6a9fa3168b39f15fafb43cb9a6070"),
                                b'\x01' * 32,
                                child_index=UINT32_MAX + 1)

        # hardened index for pub child
        with self.assertRaises(Exception):
            BIP32Node.child_pub(b'\x00', b'\x01', child_index=HARDENED_INDEX)

    def test_random_things(self):
        seed = bytes.fromhex("1077a46dc8545d372f22d9e110ae6c5c2bf7620fe9c4c911f5404d112233e1aa"
                             "270567dd3554092e051ba3ba86c303590b0309116ac89964ff284db2219d7511")
        first_bip32 = BIP32Node.from_root_seed(seed,
                                               Network.MAIN_PRIVATE)
        secnd_bip32 = BIP32Node.from_any_xkey("xprv9s21ZrQH143K3o4KUs47P2x9afhH31ekMo2foNTYwrU9wwZ8g5E"
                                              "atR9bn6YmCacdvnHWMnPFUqieQrnunrzuF5UfgGbhbEW43zRnhpPDBUL")
        self.assertEqual(first_bip32.get_xprv(), secnd_bip32.get_xprv())
        self.assertEqual(first_bip32.get_xpub(), secnd_bip32.get_xpub())

        # tests if 'from_root_seed' and 'from_any_xkey' produce same root node, and child nodes
        for i in range(50):
            path = [int.from_bytes(os.urandom(3), "big") for _ in range(5)]
            hardened_path = [
                HARDENED_INDEX + int.from_bytes(os.urandom(3), "big") for _ in range(5)
            ]
            mixed_path = [int.from_bytes(os.urandom(3), "big") for _ in range(5)]
            for i in mixed_path:
                if int.from_bytes(os.urandom(32), "big") % 2:
                    i += HARDENED_INDEX

            self.assertEqual(first_bip32.child_xprv_node(parse_path_as_str(path)).get_xprv(),
                             secnd_bip32.child_xprv_node(parse_path_as_str(path)).get_xprv())
            self.assertEqual(first_bip32.child_xpub_node(parse_path_as_str(path)).get_xpub(),
                             secnd_bip32.child_xpub_node(parse_path_as_str(path)).get_xpub())

            self.assertEqual(first_bip32.child_xprv_node(parse_path_as_str(hardened_path)).get_xprv(),
                             secnd_bip32.child_xprv_node(parse_path_as_str(hardened_path)).get_xprv())
            self.assertEqual(first_bip32.child_xprv_node(parse_path_as_str(hardened_path)).get_xpub(),
                             secnd_bip32.child_xprv_node(parse_path_as_str(hardened_path)).get_xpub())

            self.assertEqual(first_bip32.child_xprv_node(parse_path_as_str(mixed_path)).get_xprv(),
                             secnd_bip32.child_xprv_node(parse_path_as_str(mixed_path)).get_xprv())
            self.assertEqual(first_bip32.child_xprv_node(parse_path_as_str(mixed_path)).get_xpub(),
                             secnd_bip32.child_xprv_node(parse_path_as_str(mixed_path)).get_xpub())

        # random from iancoleman
        # spanish,  24 word, eth
        master_node = BIP32Node.from_root_seed(
            bytes.fromhex("f20fcda8b49581e42c38fc077202a1f5d25377e3e1da9d4e92084d3ab4e1784415"
                          "0fced8f755f629d2b0d477acac21c314f7d26833f8e5aa31d09cf6e6c748b3"),
            Network.MAIN_PRIVATE
        )
        self.assertEqual(master_node.get_xprv(),
                         "xprv9s21ZrQH143K4KFWo9Akh3rKMkrBSV3tkXUabsckqojADNmLMGjmgg1QLrpfbRcvfjgQ95hAF1ZFeMDYV3Av345Vgfqzx1JHWNBvBthyv4P")
        self.assertEqual(master_node.get_xpub(),
                         "xpub661MyMwAqRbcGoKyuAhm4Bo3ungfqwmk7kQBQG2NQ9G96B6Utp42EUKtCAu58uN38Pnu1jPBd2ynCZ4LMaxMEiqGHdGdFrw5vkLob9Vdrqj")
        # italian, 21 word, eth
        master_node = BIP32Node.from_root_seed(
            bytes.fromhex("5d0be5e88c285ff1fc2d0438fe2df42f8db8944ef3d2dabdf80e1a23b37dde70b7a"
                          "5870b3169f54217c68ab6dde0dbc99d34717caac81e2fd9fa8f61a4ea4614"),
            Network.MAIN_PRIVATE
        )
        self.assertEqual(master_node.get_xprv(),
                         "xprv9s21ZrQH143K2vwFLyKCdNbXrGWYJZcSDkeN1SX6PY3Hv9zYgzpgBjrBoRPsuEynk1MzLcjdMk6FQ1NqzB2qWut9s6SEZGQiUDQXM5iJYyd")
        self.assertEqual(master_node.get_xpub(),
                         "xpub661MyMwAqRbcFR1iSzrCzWYGQJM2i2LHayZxopvhwsaGnxKhEY8vjYAfei7CKoVLCpgTPKiYreg5iJC5J7LufQscy1Zt54VNmK8gaGmseJG")
        self.assertEqual(master_node.child_xprv_node("m/234/9435'/2324'/343/984").get_xprv(),
                         "xprvA3hfY3etsJHoVwQsdBcyfeMkJ4qfjRNFvWLZtKnKvy6fVRzL2532sQZLgFzhBPvHkv57CFoLaj1XmG8w6vuDWvy85pbhC3uXH6iQcpg2qHh")
        self.assertEqual(master_node.child_xpub_node("m/234/9435/0/343/83324").get_xpub(),
                         "xpub6H5ESXD8nx9jQkyqrrRLsbBdzquP46Hbd1HPJMmYDcWHW4WgAUxaezDg7R1bToNPMs1cnSaCvLEU1SbFJKbrBdUBmqz7F8dN9DN4GYLCvyx")

        # multiple tests from this master_node
        master_node = BIP32Node.from_root_seed(
            bytes.fromhex("ac8c2377e5cde867d7e420fbe04d8906309b70d51b8fe58d6844930621a9bc22392"
                          "9155dcfebb4da9d62c86ec0d15adf936a663f4f0cf39cbb0352e7dac073d6"),
            Network.MAIN_PRIVATE
        )
        self.assertEqual(master_node.get_xprv(),
                         "xprv9s21ZrQH143K2GzaKJsW7DQsxeDpY3zqgusaSx6owWGC19k4mhwnVAsm4qPsCw43NkY2h1BzVLyxWHt9NKF86QRyBj53vModdGcNxtpD6KX")
        self.assertEqual(master_node.get_xpub(),
                         "xpub661MyMwAqRbcEm53RLQWUMMcWg4JwWih48oBFLWRVqoAsx5DKFG32yCEv8iH29TWpmo5KTcpsjXcea6Zx4Hc6PAbGnHjEDCf3yHbj7qdpnf")

        # sanity checks for m/0'/0'/14/0'/18
        path = parse_path_as_str([HARDENED_INDEX, HARDENED_INDEX, 14, HARDENED_INDEX, 18])
        xprv = master_node.child_xprv_node(path).get_xprv()
        xpub = master_node.child_xprv_node(path).get_xpub()
        self.assertEqual(xprv,
                         "xprvA2YVbLvEeKaPedw7F6RLwG3RgYnTq1xGCyDNMgZNWdEQnSUBQmKEuLyA6TSPsggt5xvyJHLD9L25tNLpQiP4Q8ZkQNo8ueAgeYj5zYq8hSm")
        self.assertEqual(xpub,
                         "xpub6FXqzrT8Uh8gs81aM7xMJPzAEacxEUg7aC8yA4xz4xmPfEoKxJdVT9Hdwm3LwVQrSos2rhGDt8aGGHvdLr5LLAjK8pXFkbSpzGoGTXjd4z9")

        # continue above: now if our master is m/0'/0'/14, we should derive the same keys for m/0'/0'/14/0'/18
        path = parse_path_as_str([HARDENED_INDEX, HARDENED_INDEX, 14])
        path2 = parse_path_as_str([HARDENED_INDEX, 18])
        xprv2 = master_node.child_xprv_node(path).get_xprv()
        self.assertEqual(xprv2,
                         "xprv9yQJmvQMywM5i7UNuZ4RQ1A9rEMwAJCExPardkmBCB46S3vBqNEatSwLUrwLNLHBu1Kd9aGxGKDD5YAfs6hRzpYthciAHjtGadxgV2PeqY9")
        master_node = BIP32Node.from_any_xkey(xprv2)
        self.assertEqual(master_node.get_xprv(), xprv2)
        self.assertEqual(master_node.child_xprv_node(path2).get_xprv(), xprv)
        self.assertEqual(master_node.child_xprv_node(path2).get_xpub(), xpub)

        # recognize the networks..
        # .. for xprvs:
        master_node = BIP32Node.from_any_xkey("xprv9wHokC2KXdTSpEepFcu53hMDUHYfAtTaLEJEMyxBPAMf78hJg17WhL5Fy"
                                              "eDUQH5KWmGjGgEb2j74gsZqgupWpPbZgP6uFmP8MYEy5BNbyET")
        self.assertEqual(master_node.network, Network.MAIN_PRIVATE)
        master_node = BIP32Node.from_any_xkey("tprv8ZgxMBicQKsPeCBsMzQCCb5JcW4S49MVL3EwhdZMF1RF71rgisZU4"
                                              "ZRvrHX6PZQEiNUABDLvYqpx8Lsccq8aGGR59qHAoLoE3iXYuDa8JTP")
        self.assertEqual(master_node.network, Network.TEST_PRIVATE)

        # .. for xpubs:
        master_node = BIP32Node.from_any_xkey("xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw"
                                              "2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU")
        self.assertEqual(master_node.network, Network.MAIN_PUBLIC)
        master_node = BIP32Node.from_any_xkey("tpubD6NzVbkrYhZ4WN3WiKRjeo2eGyYNiKNg8vcQ1UjLNJJaDvoF"
                                              "hmR1XwJsbo5S4vicSPoWQBThR3Rt8grXtP47c1AnoiXMrEmFdRZupxJzH1j")
        self.assertEqual(master_node.network, Network.TEST_PUBLIC)

        # create valid network
        self.assertTrue(BIP32Node.from_root_seed(os.urandom(32), Network.TEST_PUBLIC, check_seed_len=False)
                        .get_xpub().startswith("tpub"))
        self.assertTrue(BIP32Node.from_root_seed(os.urandom(32), Network.TEST_PRIVATE, check_seed_len=False)
                        .get_xprv().startswith("tprv"))
        self.assertTrue(BIP32Node.from_root_seed(os.urandom(32), Network.MAIN_PUBLIC, check_seed_len=False)
                        .get_xpub().startswith("xpub"))
        self.assertTrue(BIP32Node.from_root_seed(os.urandom(32), Network.MAIN_PRIVATE, check_seed_len=False)
                        .get_xprv().startswith("xprv"))

        # raise if we attempt to use a prvKey without prvKey access
        master_node = BIP32Node.from_any_xkey("xpub6C6zm7YgrLrnd7gXkyYDjQihT6F2ei9EYbNuSiDAjok7Ht56D"
                                              "5zbnv8WDoAJGg1RzKzK4i9U2FUwXG7TFGETFc35vpQ4sZBuYKntKMLshiq")
        # no exception
        master_node.get_xpub()
        master_node.child_xpub_node("m/0/1")
        master_node.child_xpub_node("m/10000/18")
        # exception
        with self.assertRaises(Exception):
            master_node.get_xprv()
        with self.assertRaises(Exception):
            master_node.child_xprv_node("m/0/1/2").get_xprv()
        with self.assertRaises(Exception):
            master_node.child_xprv_node(parse_path_as_str([9, 8])).get_xprv()
        with self.assertRaises(Exception):
            master_node.child_xprv_node("m/0'/1").get_xpub()
        with self.assertRaises(Exception):
            master_node.child_xprv_node("m/10000'/18").get_xpub()


if __name__ == "__main__":
    unittest.main()
