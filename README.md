Hierarchically Deterministic wallet/address generator for `ERC-20`/`BEP-20` coins

### Build 'libsecp256k1'

<details>
<summary>macOS</summary>

```shell
brew install autoconf automake libtool

cd src/contrib

# might be necessary
chmod a+x make_libsecp256k1.sh

# build libsecp256k1 on host machine (architecture dependent) 
./make_libsecp256k1.sh
```

</details>

### Usage

#### BIP39: Mnemonic Seed module

Generate Mnemonic phrase

###### Create

```python
supported_languages = Mnemonic.get_languages()
# chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish

mnemonic = Mnemonic("spanish")

wordlist = mnemonic.get_wordlist()
# ['ábaco', 'abdomen', 'abeja', 'abierto', 'abogado', 'abono', 'aborto', 'abrazo', 'abrir', 'abuelo', ...]
```

###### Generate mnenomic phrase

```python
# possible strength are 128, 160, 192, 224, 256. 
#   128->12 words, 256->24 words
mnemonic_phrase = mnemonic.generate(strength=128)
# informe vehículo lección toque clan bebé batería química ver azul este orilla

# or you can use 16, 20, 24, 28, 32 length of `bytes` directly
# mnemonic_phrase = mnemonic.to_mnemonic(entropy_bytes)
```

###### Other methods

```python
valid = mnemonic.is_mnemonic_valid("informe vehículo lección toque clan bebé batería química ver azul este orilla")
# True

word = mnemonic.expand_word("infor")
# informe

mnemonic_phrase = mnemonic.expand("infor veh lecc toq clan bebé bate química ver azul este orilla")
# informe vehículo lección toque clan bebé batería química ver azul este orilla

entropy = mnemonic.to_entropy("informe vehículo lección toque clan bebé batería química ver azul este orilla")
entropy_hex = entropy.hex()
# 72becdf1f563363b073dfff823454353
```

###### Static methods

```python
supported_languages = Mnemonic.get_languages()
# chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish

detected_language = Mnemonic.detect_language("cartolina neretto capsula verifica spinoso negozio "
                                             "genotipo taverna vissuto guardare girone eclissi")
# italian

seed = Mnemonic.to_seed("cartolina neretto capsula verifica spinoso negozio "
                        "genotipo taverna vissuto guardare girone eclissi")
seed_hex = seed.hex()
# c9864757b69270fbcc252d38019991261f836d48d72f0298fb25f5fcb4fbe10ebadd77692a1414c551c67158ff5a6a30fcff0d702dee49159f81520ad65b3553

master_xprv = Mnemonic.to_master_xprv(seed, Network.MAIN_PRIVATE)
# xprv9s21ZrQH143K2inwH5RXdjGY2akE2KGK5z52NXtairdEVq8o6ZcLmx8MnctG82d8VcD9AgCNe8nCcqAcZwAiPXB6PnqPPNp2qcEmLVasqAN
```

#### BIP32, BIP44: HD Wallet module

Generate Hierarchically Deterministic addresses

###### Builder methods

```python
# seed of mnemonic: "cartolina neretto capsula verifica spinoso negozio genotipo taverna vissuto guardare girone eclissi"
seed = bytes.fromhex("c9864757b69270fbcc252d38019991261f836d48d72f0298fb25f5fcb4fbe10ebadd"
                     "77692a1414c551c67158ff5a6a30fcff0d702dee49159f81520ad65b3553")
node_from_seed = BIP32Node.from_root_seed(seed, Network.MAIN_PRIVATE)
node_from_xprv = BIP32Node.from_any_xkey("xprv9s21ZrQH143K2inwH5RXdjGY2akE2KGK5z52NXtairdEVq8o6ZcLm"
                                         "x8MnctG82d8VcD9AgCNe8nCcqAcZwAiPXB6PnqPPNp2qcEmLVasqAN")
node_from_seed.get_xprv()
node_from_xprv.get_xprv()
# xprv9s21ZrQH143K2inwH5RXdjGY2akE2KGK5z52NXtairdEVq8o6ZcLmx8MnctG82d8VcD9AgCNe8nCcqAcZwAiPXB6PnqPPNp2qcEmLVasqAN
node_from_seed.get_xpub()
node_from_xprv.get_xpub()
# xpub661MyMwAqRbcFCsQP6xXzsDGacaiRmzATCzdAvJCHCADNdTwe6vbKkSqdtZxn2iLcE4zdtp9FRqZFC7G7V1SK2MfQMWn5stKGAzCSdXnn6T
```

###### Static methods

```python
# seed of mnemonic: "cartolina neretto capsula verifica spinoso negozio genotipo taverna vissuto guardare girone eclissi"
seed = bytes.fromhex("c9864757b69270fbcc252d38019991261f836d48d72f0298fb25f5fcb4fbe10ebadd"
                     "77692a1414c551c67158ff5a6a30fcff0d702dee49159f81520ad65b3553")
node = BIP32Node.from_root_seed(seed, Network.MAIN_PRIVATE)

depth = node.depth
# 0
parent_fingerprint = node.parent_fingerprint
# b'\x00\x00\x00\x00'
child_index = node.child_index
# b'\x00\x00\x00\x00'
chain_code = node.chain_code
# b'B\x8f\x9c\x936\xabU\xec\x884\x88i\xbd\xf0\xbd\x80\x7fW\x8b\x01?\x01\x0b\xc8\xd8\x0ff\xb7Yd/\x10'
# hex(): 428f9c9336ab55ec88348869bdf0bd807f578b013f010bc8d80f66b759642f10
pub = node.ec_key.get_pubkey()
# hex(): 02ce35f48c849dc5ed34c80d2cc7497605612af4b2ad439230c7d6fa290425ba70

xkey_without_checksum = BIP32Node.build_xkey_wo_checksum(
    VERSION_BYTES[Network.MAIN_PRIVATE],
    depth,
    parent_fingerprint,
    child_index,
    chain_code,
    pub
)
# b'\x04\x88\xad\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00B\x8f\x9c\x936\xabU\xec\x884\x88i\xbd\xf0\xbd\x80\x7fW\x8b\x01?\x01\x0b\xc8\xd8\x0ff\xb7Yd/\x10\x02\xce5\xf4\x8c\x84\x9d\xc5\xed4\xc8\r,\xc7Iv\x05a*\xf4\xb2\xadC\x920\xc7\xd6\xfa)\x04%\xbap'
# hex(): 0488ade4000000000000000000428f9c9336ab55ec88348869bdf0bd807f578b013f010bc8d80f66b759642f1002ce35f48c849dc5ed34c80d2cc7497605612af4b2ad439230c7d6fa290425ba70

(child_prv, child_cc) = BIP32Node.child_prv(parent_prv=node.ec_key.get_prv_key(),
                                            parent_cc=node.chain_code,
                                            child_index=1)
# child_prv.hex(): ccee88944ef5b2a12de93402675db7a93c76a41987e05d430be0befd932e1861
# child_cc.hex(): 649b6c76ae584d19a287d0d91706683850dee217eb52f7a828053898b6ba2763

(child_pub, child_cc_2) = BIP32Node.child_pub(parent_pub=node.ec_key.get_pubkey(),
                                              parent_cc=node.chain_code,
                                              child_index=1)
# child_pub.hex(): 03347747d9d200d58bc8056c4aba3d960ee86f29141fd07aefdfd604b77d35e0db
# child_cc_2.hex(): 649b6c76ae584d19a287d0d91706683850dee217eb52f7a828053898b6ba2763
```

###### Derivation methods

```python
seed = bytes.fromhex("c9864757b69270fbcc252d38019991261f836d48d72f0298fb25f5fcb4fbe10ebadd"
                     "77692a1414c551c67158ff5a6a30fcff0d702dee49159f81520ad65b3553")
parent_prv_netw = BIP32Node.from_root_seed(seed, Network.MAIN_PRIVATE)
parent_pub_netw = BIP32Node.from_root_seed(seed, Network.MAIN_PUBLIC)

some_child_prv = parent_prv_netw.child_xprv_node("m/44'/60'/0'/12")
# get_p2pkh_address(): 0x813A5bDe72EBE160642bec7C0f89a2c9A408065B
some_child_pub = parent_pub_netw.child_xpub_node("m/44/60/0/12")
# get_p2pkh_address(): 0x1eBb371F1858C4B54f3A253Cc71B0e03Ae0790A3
```

###### Other methods

```python
node.is_private()
node.get_self_fingerprint()
node.get_child_index_as_str()
node.get_xprv()
node.get_xpub()
node.convert_to_public()
node.get_p2pkh_address()
```