#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2013 Pavol Rusnak
# Copyright (c) 2017 mruddy
# Copyright (c) 2022 Jemshit Iskenderov
#

import json
import os
import random
import unittest

from src.common.network import Network
from src.common.util import normalize_string
from src.mnemonic_seed.mnemonic import Mnemonic


class MnemonicTest(unittest.TestCase):
    _english_file_path = os.path.join(os.path.dirname(__file__), 'english_mnemonic_vectors.json')
    _japanese_file_path = os.path.join(os.path.dirname(__file__), 'japanese_mnemonic_vectors.json')

    def test_get_languages(self):
        # empty cache
        Mnemonic.cached_language_list.clear()
        self.assertEqual([], Mnemonic.cached_language_list)

        # all list
        expected = ["chinese_simplified", "chinese_traditional", "english",
                    "french", "italian", "japanese", "korean", "spanish"]
        actual = sorted(Mnemonic.get_languages())
        self.assertEqual(expected, actual)

        # cached
        self.assertNotEqual([], Mnemonic.cached_language_list)

    def test_get_wordlist(self):
        Mnemonic.cached_wordlists.clear()
        mnemonic = Mnemonic("english")

        # 1 cached
        self.assertEqual(1, len(Mnemonic.cached_wordlists.keys()))

        # length
        actual = mnemonic.get_wordlist()
        self.assertEqual(2048, len(actual))

        # 2 cached
        Mnemonic("japanese")
        self.assertEqual(2, len(Mnemonic.cached_wordlists.keys()))

        # unknown language
        with self.assertRaises(Exception):
            Mnemonic("xxx")

    def test_language_detection(self):
        self.assertEqual("english", Mnemonic.detect_language("security"))
        self.assertEqual("french", Mnemonic.detect_language("abreuver"))
        self.assertEqual("japanese", Mnemonic.detect_language("あこがれる"))

        # chinese simplified & chinese tradition intersection -> returns chinese simplified
        self.assertEqual("chinese_simplified", Mnemonic.detect_language("的"))

        # doesn't exist
        with self.assertRaises(Exception):
            Mnemonic.detect_language("xxxxxxx")

        # doesn't exist
        with self.assertRaises(Exception):
            Mnemonic.detect_language("coursera")

        # exists in french & english
        with self.assertRaises(Exception):
            Mnemonic.detect_language("canal")

    def test_is_mnemonic_valid(self):
        # fails cuz of checksum, italian
        words = "abolire capra cullato ampliare ombelico seme spirale udire zucchero riunione parlato luminoso"
        mnemonic = Mnemonic("italian")
        self.assertFalse(mnemonic.is_mnemonic_valid(words))

        # fails cuz of checksum, english
        words = "bless cloud wheel regular tiny venue bird web grief security dignity zoo"
        mnemonic = Mnemonic("english")
        self.assertFalse(mnemonic.is_mnemonic_valid(words))

        # incorrect word count
        words = "below"
        mnemonic = Mnemonic("english")
        self.assertFalse(mnemonic.is_mnemonic_valid(words))

        # success
        words = "bus vacuum range clutch vacuum bench top figure season achieve wood unable romance panic rotate"
        mnemonic = Mnemonic("english")
        self.assertTrue(mnemonic.is_mnemonic_valid(words))

        # success, korean
        words = "금지 한때 작품 단위 한때 광주 특성 부인 조용히 가장 회전 하늘 절약 월세 점원"
        mnemonic = Mnemonic("korean")
        self.assertTrue(mnemonic.is_mnemonic_valid(words))

        # success, duplicate words
        words = "audit again guess butter minute predict grid image fresh kit west will before noodle supply magic bread protect mimic butter credit tragic recipe clarify"
        mnemonic = Mnemonic("english")
        self.assertTrue(mnemonic.is_mnemonic_valid(words))

        # success, duplicate words
        words = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        mnemonic = Mnemonic("english")
        self.assertTrue(mnemonic.is_mnemonic_valid(words))

    def test_to_seed_utf8_nfkd(self):
        # The same sentence in various UTF-8 forms
        words_nfkd = u"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"
        words_nfc = u"P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfkc = u"P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfd = u"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"

        passphrase_nfkd = (
            u"Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko"
        )
        passphrase_nfc = (
            u"Neuv\u011b\u0159iteln\u011b bezpe\u010dn\xe9 hesl\xed\u010dko"
        )
        passphrase_nfkc = (
            u"Neuv\u011b\u0159iteln\u011b bezpe\u010dn\xe9 hesl\xed\u010dko"
        )
        passphrase_nfd = (
            u"Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko"
        )

        seed_nfkd = Mnemonic.to_seed(words_nfkd, passphrase_nfkd)
        seed_nfc = Mnemonic.to_seed(words_nfc, passphrase_nfc)
        seed_nfkc = Mnemonic.to_seed(words_nfkc, passphrase_nfkc)
        seed_nfd = Mnemonic.to_seed(words_nfd, passphrase_nfd)

        self.assertEqual(seed_nfkd, seed_nfc)
        self.assertEqual(seed_nfkd, seed_nfkc)
        self.assertEqual(seed_nfkd, seed_nfd)

    def test_generate(self):
        mnemonic = Mnemonic("french")
        for _ in range(10):
            self.assertTrue(mnemonic.is_mnemonic_valid(mnemonic.generate(128)))
        for _ in range(10):
            self.assertTrue(mnemonic.is_mnemonic_valid(mnemonic.generate(192)))
        for _ in range(10):
            self.assertTrue(mnemonic.is_mnemonic_valid(mnemonic.generate(256)))

        # invalid strength
        with self.assertRaises(Exception):
            mnemonic.generate(100)

    def test_to_mnemonic(self):
        mnemonic = Mnemonic("english")

        # correct, 15 words
        input = bytes.fromhex("1efe12c7164f082a393ab0c2203bf4f62bb93f6f")
        expected = "bus vacuum range clutch vacuum bench top figure season achieve wood unable romance panic rotate"
        actual = mnemonic.to_mnemonic(input)
        self.assertEqual(expected, actual)

        # correct, 15 words
        input = bytes.fromhex("3f666c64902146c1112e950c0844507eb1a9c371")
        expected = "disorder cricket bomb cake behave gauge dwarf sport army drama beef word box ticket settle"
        actual = mnemonic.to_mnemonic(input)
        self.assertEqual(expected, actual)

        # japanese, 12 words
        mnemonic = Mnemonic("japanese")
        input = bytes.fromhex("d30c42631f695cbe3b6674699935d9cb1bef9ca370637c1bbb3c837c")
        expected = "ふくざつ　しうち　つかう　くらす　ちほう　さよく　もえる　ひめい　しゃそう　ひかく　せつでん　ちみどろ　のりゆき　ひまん　たよる　いっそう　ぜんりゃく　ほしょう　びょうき　いいだす　びょうき"
        actual = mnemonic.to_mnemonic(input)
        # strings weren't appearing in normalized form as copied from <https://iancoleman.io/bip39/>
        self.assertEqual(normalize_string(expected), normalize_string(actual))

    def test_english_vectors(self):
        with open(self._english_file_path, "r") as file:
            vectors = json.load(file)
            #           [
            # entropy:    "00000000000000000000000000000000",
            # words:      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            # seed:       "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            # master_sk:  "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
            #           ]

        mnemonic = Mnemonic("english")
        for row in vectors:
            entropy = row[0]
            expected = row[1]
            expected_seed = row[2]
            expected_xprv = row[3]

            actual = mnemonic.to_mnemonic(bytes.fromhex(entropy))
            seed = Mnemonic.to_seed(actual, passphrase="TREZOR")
            xprv = Mnemonic.to_master_xprv(seed, Network.MAIN_PRIVATE)

            self.assertEqual(expected, actual)
            self.assertEqual(expected_seed, seed.hex())
            self.assertEqual(expected_xprv, xprv)

    def test_japanese_vectors(self):
        with open(self._japanese_file_path, "r") as file:
            vectors = json.load(file)
            # entropy, expected_mnemonic, passphrase, expected_seed

        mnemonic = Mnemonic("japanese")
        for row in vectors:
            entropy = row[0]
            expected_mnemonic = row[1]
            passphrase = row[2]
            expected_seed = row[3]

            words = mnemonic.to_mnemonic(bytes.fromhex(entropy))
            self.assertTrue(mnemonic.is_mnemonic_valid(words))

            # for some reason, the strings weren't appearing in normalized form as copied from BIP39 test vectors
            self.assertEqual(normalize_string(expected_mnemonic), normalize_string(words))

            seed = Mnemonic.to_seed(words, passphrase)
            self.assertEqual(expected_seed, seed.hex())

            # check this because we had to normalize the string for unicode artifacts
            seed = Mnemonic.to_seed(expected_mnemonic, passphrase)
            self.assertEqual(expected_seed, seed.hex())

    def test_expand_word(self):
        mnemonic = Mnemonic("english")

        # empty
        self.assertEqual("", mnemonic.expand_word(""))
        self.assertEqual(" ", mnemonic.expand_word(" "))

        # word in list -> no expand required
        self.assertEqual("access", mnemonic.expand_word("access"))

        # unique prefix (in english) expanded to word in list -> expand
        self.assertEqual("access", mnemonic.expand_word("acce"))

        # not found at all -> can't expand
        self.assertEqual("acb", mnemonic.expand_word("acb"))

        # multi-prefix match -> can't expand
        self.assertEqual("acc", mnemonic.expand_word("acc"))

        # exact three letter match -> no expand required
        self.assertEqual("act", mnemonic.expand_word("act"))

        # unique prefix expanded to word in list -> expand
        self.assertEqual("action", mnemonic.expand_word("acti"))

    def test_expand(self):
        mnemonic = Mnemonic("english")

        self.assertEqual("access", mnemonic.expand("access"))

        #
        expected = "access access acb acc act action"
        input = "access acce acb acc act acti"
        self.assertEqual(expected, mnemonic.expand(input))

    def test_to_entropy(self):
        # random entropy
        entropies = [bytes(random.getrandbits(8) for _ in range(32)) for _ in range(1024)]
        # manual entropy
        entropies.append(bytes("Lorem ipsum dolor sit amet amet.", "utf-8"))

        mnemonic = Mnemonic("english")
        for expected in entropies:
            actual = mnemonic.to_entropy(mnemonic.to_mnemonic(expected).split())
            self.assertEqual(expected, actual)

    def test_to_master_xprv(self):
        # english, 24 words
        seed = bytes.fromhex(
            "6378b2364b2c1576fcda74f68ce0f3492c1766bf02333f9301018419990552de6794468b1a67a9812acc19c64479cb2cbb101d42b7ef333fb30d9296458d0ff0",
        )
        expected = "xprv9s21ZrQH143K2C4PKmguvsQt4K1uadTUg1nLjd6KsL21UbkJUNgkZmXBNphJgic5XBH4QwENfFG4UUoRg2ftKPNP3AVHk7M11y1XjGuzKg6"
        actual = Mnemonic.to_master_xprv(seed, Network.MAIN_PRIVATE)
        self.assertEqual(expected, actual)

        # spanish, 24 words
        seed = bytes.fromhex(
            "babd97b456fe7aaed9da86d3d8fd3c170fcb8355ec1d93e317c89a7417858b8450572ca9c0c89afaca50882ca3ae34b5ec041b958e71bb2d2f3f4b1e0dec1a8b",
        )
        expected = "xprv9s21ZrQH143K3xFoBoERj7CVahzNaS73vdXe7Azd1xUBBcBQsHQgpTZcJiLyuEiLWBWgY1jUav7cZxf8cro5RpAoJB2ThT4VHkxiRv7AUHZ"
        actual = Mnemonic.to_master_xprv(seed, Network.MAIN_PRIVATE)
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
