- Code must fail early if anything unexpected occurs, instead of generating wrong key/address!
- Denote Types for most of the codes, because `int`/`bytes` are mostly interlaced. If Type is explicitly denoted, it is
  easy to read the code
- Denote how many bytes a variable is, when necessary. Check for input length
- `src/contrib/make_libsecp256k1.sh` must be run first, it will install native `libsecp256k1` C library under root `src`
  dir. It is required for elliptic curve operations. Some libs use <https://github.com/tlsfuzzer/python-ecdsa> which is
  not safe. Maybe <https://github.com/ofek/coincurve/> can be safe
  alternative. <https://github.com/darosior/python-bip32> itself tries to move from `coincurve`
  to <https://github.com/rustyrussell/secp256k1-py>
  (which is experimental)
- Generated keys stay on RAM, run this on safe environment
- Follow the code style presented here for "function parameters and return type with newlines"
- When converting mnemonic->seed, `"mnemonic" + ""` used as default password. Password can be used for extra security
  and default can be used as honeypot
