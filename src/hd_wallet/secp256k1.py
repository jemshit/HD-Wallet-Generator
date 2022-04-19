# MIT License
#
# Source: <https://github.com/richardkiss/pycoin> pycoin/ecdsa/native/secp256k1.py
#

import ctypes
import os
import sys
from ctypes import (
    c_int, c_uint, c_char_p, c_size_t, c_void_p
)

SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
# /** The higher bits contain the actual data. Do not use directly. */
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
# /** Flags to pass to secp256k1_context_create. */
SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)


def load_library():
    if sys.platform == 'darwin':
        library_paths = (os.path.join(os.path.dirname(__file__), '../libsecp256k1.0.dylib'), 'libsecp256k1.0.dylib')
    elif sys.platform in ('windows', 'win32'):
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1-0.dll'), 'libsecp256k1-0.dll')
    elif 'ANDROID_DATA' in os.environ:
        library_paths = ('libsecp256k1.so',)
    else:  # desktop Linux and similar
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1.so.0'), 'libsecp256k1.so.0')

    exceptions = []
    secp256k1 = None
    for libpath in library_paths:
        try:
            secp256k1 = ctypes.cdll.LoadLibrary(libpath)
        except BaseException as e:
            exceptions.append(e)
        else:
            break
    if not secp256k1:
        raise Exception(f'libsecp256k1 library failed to load. exceptions: {repr(exceptions)}')

    try:
        secp256k1.secp256k1_context_create.argtypes = [c_uint]
        secp256k1.secp256k1_context_create.restype = c_void_p

        secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
        secp256k1.secp256k1_context_randomize.restype = c_int

        secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_create.restype = c_int

        secp256k1.secp256k1_ecdsa_sign.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
        secp256k1.secp256k1_ecdsa_sign.restype = c_int

        secp256k1.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_verify.restype = c_int

        secp256k1.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t]
        secp256k1.secp256k1_ec_pubkey_parse.restype = c_int

        secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_uint]
        secp256k1.secp256k1_ec_pubkey_serialize.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_normalize.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_normalize.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t]
        secp256k1.secp256k1_ecdsa_signature_parse_der.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = c_int

        secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = c_int

        secp256k1.secp256k1_ec_pubkey_combine.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
        secp256k1.secp256k1_ec_pubkey_combine.restype = c_int

        # --enable-module-recovery
        try:
            secp256k1.secp256k1_ecdsa_recover.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
            secp256k1.secp256k1_ecdsa_recover.restype = c_int

            secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p,
                                                                                      c_int]
            secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = c_int
        except (OSError, AttributeError):
            raise Exception('libsecp256k1 library found but it was built '
                            'without required module (--enable-module-recovery)')

        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        ret = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        if not ret:
            raise Exception('secp256k1_context_randomize failed')

        return secp256k1
    except (OSError, AttributeError) as e:
        raise Exception(f'libsecp256k1 library was found and loaded but there was an error when using it: {repr(e)}')


_libsecp256k1 = None
try:
    _libsecp256k1 = load_library()
except BaseException as e:
    raise Exception(f'failed to load libsecp256k1: {repr(e)}')

if _libsecp256k1 is None:
    # hard fail:
    sys.exit(f"Error: Failed to load libsecp256k1.")
