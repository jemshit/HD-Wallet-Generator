#
# Copyright (c) 2022 Jemshit Iskenderov
#

import binascii
from enum import Enum, auto


class Network(Enum):
    MAIN_PRIVATE = auto()
    MAIN_PUBLIC = auto()
    TEST_PRIVATE = auto()
    TEST_PUBLIC = auto()

    def is_private(self) \
            -> bool:
        if self is Network.MAIN_PRIVATE or self is Network.TEST_PRIVATE:
            return True
        elif self is Network.MAIN_PUBLIC or self is Network.TEST_PUBLIC:
            return False
        else:
            raise Exception("Unknown Network")

    def is_public(self) \
            -> bool:
        return not self.is_private()

    def is_testnet(self) \
            -> bool:
        return self is Network.TEST_PRIVATE or self is Network.TEST_PUBLIC

    def invert(self) \
            -> 'Network':
        """
        Inverts Public to Private and vice-versa
        """

        if self is Network.MAIN_PRIVATE:
            return Network.MAIN_PUBLIC
        elif self is Network.MAIN_PUBLIC:
            return Network.MAIN_PRIVATE
        elif self is Network.TEST_PRIVATE:
            return Network.TEST_PUBLIC
        elif self is Network.TEST_PUBLIC:
            return Network.TEST_PRIVATE
        else:
            raise Exception("Unknown Network")


# Only BIP-44, P2PKH (xprv, xpub)
# Others: BIP-49 'P2WPKH-nested-in-P2SH' (yprv, ypub); BIP-84 'P2WPKH' (zprv, zpub)
VERSION_BYTES = {
    Network.MAIN_PRIVATE: binascii.unhexlify('0488ade4'),  # xprv
    Network.MAIN_PUBLIC: binascii.unhexlify('0488b21e'),  # xpub
    Network.TEST_PRIVATE: binascii.unhexlify('04358394'),  # tprv
    Network.TEST_PUBLIC: binascii.unhexlify('043587cf')  # tpub
}


def get_network_from_bytes(version_bytes: bytes) \
        -> Network:
    if version_bytes == VERSION_BYTES[Network.MAIN_PRIVATE]:
        return Network.MAIN_PRIVATE
    elif version_bytes == VERSION_BYTES[Network.MAIN_PUBLIC]:
        return Network.MAIN_PUBLIC
    elif version_bytes == VERSION_BYTES[Network.TEST_PRIVATE]:
        return Network.TEST_PRIVATE
    elif version_bytes == VERSION_BYTES[Network.TEST_PUBLIC]:
        return Network.TEST_PUBLIC
    else:
        raise Exception(f'Invalid version_bytes: {version_bytes.hex()}')


def get_private_version_byte_of(network: Network) \
        -> bytes:
    if network.is_testnet():
        return VERSION_BYTES[Network.TEST_PRIVATE]
    else:
        return VERSION_BYTES[Network.MAIN_PRIVATE]


def get_public_version_byte_of(network: Network) \
        -> bytes:
    if network.is_testnet():
        return VERSION_BYTES[Network.TEST_PUBLIC]
    else:
        return VERSION_BYTES[Network.MAIN_PUBLIC]
