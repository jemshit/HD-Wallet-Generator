#!/usr/bin/env python3

# Copyright (c) 2022 Jemshit Iskenderov
#

import json
import os
import unittest

from src.common.util import base58_encode, binary_search, normalize_string, base58_decode, address_with_checksum, \
    UINT32_MAX, parse_path_as_str, HARDENED_INDEX, parse_path_as_uint32


class UtilsTest(unittest.TestCase):
    _b58_file_path = os.path.join(os.path.dirname(__file__), 'base58_vectors.json')
    _paths_file_path = os.path.join(os.path.dirname(__file__), 'path_vectors.json')

    def test_binary_search(self):
        # empty array
        input = []
        find = 1
        self.assertEqual(-1, binary_search(input, find))

        # not found
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 9
        self.assertEqual(-1, binary_search(input, find))

        # first item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 0
        self.assertEqual(0, binary_search(input, find))

        # last item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 16
        self.assertEqual(8, binary_search(input, find))

        # middle item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 8
        self.assertEqual(4, binary_search(input, find))

        # random item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 2
        self.assertEqual(1, binary_search(input, find))

        # random item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16]
        find = 12
        self.assertEqual(6, binary_search(input, find))

        # even length, not found
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16, 17]
        find = 19
        self.assertEqual(-1, binary_search(input, find))

        # even length, fist item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16, 17]
        find = 0
        self.assertEqual(0, binary_search(input, find))

        # even length, last item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16, 17]
        find = 17
        self.assertEqual(9, binary_search(input, find))

        # even length, middle item
        input = [0, 2, 4, 6, 8, 10, 12, 14, 16, 17]
        find = 10
        self.assertEqual(5, binary_search(input, find))

    def test_normalize_string(self):
        words_nfkd = u"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"
        words_nfc = u"P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfkc = u"P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfd = u"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"

        self.assertEqual(words_nfkd, normalize_string(words_nfkd))
        self.assertEqual(words_nfkd, normalize_string(words_nfc))
        self.assertEqual(words_nfkd, normalize_string(words_nfkc))
        self.assertEqual(words_nfkd, normalize_string(words_nfd))

    def test_base58_encode(self):
        with open(self._b58_file_path, "r") as f:
            vectors = json.load(f)

        for index, row in enumerate(vectors):
            input = bytes.fromhex(row[0])
            expected = row[1]
            self.assertEqual(expected, base58_encode(input))

    def test_base58_decode(self):
        with open(self._b58_file_path, "r") as f:
            vectors = json.load(f)

        for index, row in enumerate(vectors):
            input = row[1]
            expected = bytes.fromhex(row[0])
            self.assertEqual(expected, base58_decode(input))

    def test_path_as_uint_vectors(self):
        with open(self._paths_file_path, "r") as file:
            vectors = json.load(file)
            # path:    'm/0'
            # as list: [0]

        for row in vectors:
            path = row[0]
            expected_list = row[1]

            actual_list = parse_path_as_uint32(path)

            self.assertEqual(expected_list, actual_list)

    def test_path_as_uint_invalid_inputs(self):
        # empty path
        path = ""
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)

        # invalid paths
        path = "/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/m"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/2m/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/m2/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/2_/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/*2/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "_1/2/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)
        path = "1/-2/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)

        # index overflow
        path = f"1/{UINT32_MAX + 1}/"
        with self.assertRaises(Exception):
            parse_path_as_uint32(path)

    def test_path_as_str(self):
        path = [0]
        self.assertEqual("m/0", parse_path_as_str(path))

        path = [0, 1, 2]
        self.assertEqual("m/0/1/2", parse_path_as_str(path))

        path = [0, HARDENED_INDEX + 1, 2]
        self.assertEqual("m/0/1'/2", parse_path_as_str(path))

        path = [0, HARDENED_INDEX - 1, HARDENED_INDEX + 2]
        self.assertEqual(f"m/0/{HARDENED_INDEX - 1}/2'", parse_path_as_str(path))

    def test_path_as_str_invalid_inputs(self):
        # invalid paths
        path = ['a']
        with self.assertRaises(Exception):
            parse_path_as_str(path)
        path = [2, 3, 4, -1]
        with self.assertRaises(Exception):
            parse_path_as_str(path)
        path = [2, 3, 4, UINT32_MAX + 1]
        with self.assertRaises(Exception):
            parse_path_as_str(path)
        path = [UINT32_MAX + 1]
        with self.assertRaises(Exception):
            parse_path_as_str(path)

    def test_checksum_address(self):
        # all caps
        address = "0x52908400098527886E0F7030069857D2E4169EE7"
        self.assertEqual(address, address_with_checksum(address))
        address = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
        self.assertEqual(address, address_with_checksum(address))

        # all Lower
        address = "0xde709f2102306220921060314715629080e2fb77"
        self.assertEqual(address, address_with_checksum(address))
        address = "0x27b1fdb04752bbc536007a920d24acb045561c26"
        self.assertEqual(address, address_with_checksum(address))

        # normal
        address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        self.assertEqual(address, address_with_checksum(address))
        address = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        self.assertEqual(address, address_with_checksum(address))
        address = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        self.assertEqual(address, address_with_checksum(address))
        address = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        self.assertEqual(address, address_with_checksum(address))

        # random
        address = "0x00ca5Ce763F647188F20b6B26d2B2e3c00623d36"
        self.assertEqual(address, address_with_checksum(address))
        address = "0x63b4c7B0fCed0Ef1AabDD7C55C9eFeeF6905613E"
        self.assertEqual(address, address_with_checksum(address))

        # invalid
        address = "0x001d3F1ef827552Ae1114027BD3ECF1f086bA0E9"
        self.assertNotEqual(address, address_with_checksum(address))


if __name__ == "__main__":
    unittest.main()
