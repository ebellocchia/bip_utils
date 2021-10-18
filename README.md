# BIP utility library
[![PyPI version](https://badge.fury.io/py/bip-utils.svg)](https://badge.fury.io/py/bip-utils)
[![Build Status](https://travis-ci.com/ebellocchia/bip_utils.svg?branch=master)](https://travis-ci.com/ebellocchia/bip_utils)
[![codecov](https://codecov.io/gh/ebellocchia/bip_utils/branch/master/graph/badge.svg)](https://codecov.io/gh/ebellocchia/bip_utils)
[![CodeFactor](https://www.codefactor.io/repository/github/ebellocchia/bip_utils/badge)](https://www.codefactor.io/repository/github/ebellocchia/bip_utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/ebellocchia/bip_utils/master/LICENSE)

## Introduction

This package allows generating mnemonics, seeds, private/public keys and addresses for different types of cryptocurrencies. In particular:
- Mnemonic and seed generation as defined by [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- Keys derivation as defined by [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- Derivation of a hierarchy of keys as defined by [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-0049](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) and [BIP-0084](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- Mnemonic and seed generation for [Substrate](https://wiki.polkadot.network/docs/learn-accounts#seed-generation) (Polkadot/Kusama ecosystem)
- Keys derivation for [Substrate](https://wiki.polkadot.network/docs/learn-accounts#derivation-paths) (Polkadot/Kusama ecosystem, same of Polkadot-JS)
- Mnemonic and seed generation for Monero
- Keys and addresses/subaddresses generation for Monero (same of official Monero wallet)

Other implemented functionalities:
- Parse BIP-0032 derivation paths
- Parse Substrate derivation paths
- Encode addresses for all the supported coins
- Encode/Decode [WIF](https://en.bitcoin.it/wiki/Wallet_import_format)
- Encode/Decode [base58](https://en.bitcoin.it/wiki/Base58Check_encoding#Background)
- Encode/Decode [ss58](https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58))
- Encode/Decode [segwit bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- Encode/Decode Bitcoin Cash bech32

Package dependencies:
- [crcmod](https://pypi.org/project/crcmod/) for CRC computation
- [pycryptodome](https://pypi.org/project/pycryptodome/) for keccak256 and SHA512/256
- [coincurve](https://pypi.org/project/coincurve/) for secp256k1 curve
- [ecdsa](https://pypi.org/project/ecdsa/) for nist256p1 and secp256k1 curves
- [ed25519-blake2b](https://pypi.org/project/ed25519-blake2b/) for ed25519-blake2b curve
- [pynacl](https://pypi.org/project/PyNaCl/) for ed25519 curve
- [py-sr25519-bindings](https://pypi.org/project/py-sr25519-bindings/) for sr25519 curve
- [scalecodec](https://pypi.org/project/scalecodec/) for SCALE encoding

## Supported coins

Supported BIP coins:
- Algorand
- Avalanche (all the 3 chains)
- Band Protocol
- Binance Chain
- Binance Smart Chain
- Bitcoin (and related test net)
- Bitcoin Cash (and related test net)
- BitcoinSV (and related test net)
- Cosmos
- Dash (and related test net)
- Dogecoin (and related test net)
- Elrond
- EOS
- Ethereum
- Ethereum Classic
- Fantom Opera
- Filecoin
- Harmony One (Ethereum and Cosmos addresses)
- Huobi Heco Chain
- IRIS Network
- Kava
- Kusama (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
- Litecoin (and related test net)
- Monero (based on BIP44 and secp256k1 or ed25519 SLIP-0010, it won't generate the same addresses of the official wallets but it supports subaddresses generation)
- Nano
- NEO
- OKEx Chain (Ethereum and Cosmos addresses)
- Ontology
- Polkadot (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
- Polygon
- Ripple
- Solana
- Stellar
- Terra
- Tezos
- Theta Network
- Tron
- VeChain
- Zcash (and related test net)
- Zilliqa

Supported Substrate coins:
- Acala
- Bifrost
- Chainx
- Edgeware
- Karura
- Kusama
- Moonbeam
- Moonriver
- Phala Network
- Plasm Network
- Sora
- Stafi
- Polkadot
- Generic Substrate coin

For what regards Monero, it's also possible to generate the same addresses of the official wallets without using BIP44 derivation.

Clearly, for those coins that support Smart Contracts (e.g. Ethereum, Tron, ...), the generated keys and addresses are valid for all the related tokens.\

## Install the package

For the secp256k1 curve, it's possible to use either the *coincurve* or the *ecdsa* library. *coincurve* is much faster since it's a Python wrapper to the secp256k1 C library, while *ecdsa* is a pure Python implementation.\
By default, *coincurve* will be used but it's possible to disable it when installing.

To install the package:
- Default installation (*coincurve* will be used for secp256k1)
    - Using *setuptools*:

            python setup.py install

    - Using *pip*, from this directory (local):

            pip install .

    - Using *pip*, from PyPI:

            pip install bip_utils

- Alternative installation (*ecdsa* will be used for secp256k1)
    - Using *setuptools*:

            python setup.py install --coincurve=0

    - Using *pip*, from this directory (local):

            pip install . --install-option="--coincurve=0"

    - Using *pip*, from PyPI:

            pip install bip_utils --install-option="--coincurve=0"

To run tests:

    python -m unittest discover

Or you can install *tox*:

    pip install tox

And then:
- Run tests using *pytest* (it includes code coverage and report):

        tox -e pytest

- Run tests using *coverage* (it includes code coverage and report):

        tox -e coverage

## BIP-0039 library

The BIP-0039 library allows to:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

### Mnemonic generation

A mnemonic phrase can be generated by specifying the words number (in this case a random entropy will be used) or directly by the entropy bytes.

Supported words number:

|Words number|Enum|
|---|---|
|12|*Bip39WordsNum.WORDS_NUM_12*|
|15|*Bip39WordsNum.WORDS_NUM_15*|
|18|*Bip39WordsNum.WORDS_NUM_18*|
|21|*Bip39WordsNum.WORDS_NUM_21*|
|24|*Bip39WordsNum.WORDS_NUM_24*|

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|128|*Bip39EntropyBitLen.BIT_LEN_128*|
|160|*Bip39EntropyBitLen.BIT_LEN_160*|
|192|*Bip39EntropyBitLen.BIT_LEN_192*|
|224|*Bip39EntropyBitLen.BIT_LEN_224*|
|256|*Bip39EntropyBitLen.BIT_LEN_256*|

Supported languages:

|Language|Enum|
|---|---|
|Chinese (simplified)|*Bip39Languages.CHINESE_SIMPLIFIED*|
|Chinese (traditional)|*Bip39Languages.CHINESE_TRADITIONAL*|
|Czech|*Bip39Languages.CZECH*|
|English|*Bip39Languages.ENGLISH*|
|French|*Bip39Languages.FRENCH*|
|Italian|*Bip39Languages.ITALIAN*|
|Korean|*Bip39Languages.KOREAN*|
|Portuguese|*Bip39Languages.PORTUGUESE*|
|Spanish|*Bip39Languages.SPANISH*|

**Code example**

    import binascii
    from bip_utils import Bip39EntropyBitLen, Bip39EntropyGenerator, Bip39MnemonicGenerator, Bip39WordsNum, Bip39Languages

    # Generate a random mnemonic string of 12 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)

    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())

    # Generate a random mnemonic string of 15 words by specifying the language
    mnemonic = Bip39MnemonicGenerator(Bip39Languages.ITALIAN).FromWordsNumber(Bip39WordsNum.WORDS_NUM_15)

    # Generate the mnemonic string from entropy bytes
    entropy_bytes = binascii.unhexlify(b"00000000000000000000000000000000")
    mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_bytes)
    mnemonic = Bip39MnemonicGenerator(Bip39Languages.FRENCH).FromEntropy(entropy_bytes)

    # Generate mnemonic from random 192-bit entropy
    entropy_bytes = Bip39EntropyGenerator(Bip39EntropyBitLen.BIT_LEN_192).Generate()
    mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_bytes)

### Mnemonic validation

A mnemonic string can be validated by verifying its language and checksum. Moreover, it is also possible to get back the entropy bytes from a mnemonic.\
When validating, the language can be either specified or automatically detected.\
Automatic detection takes more time, so if the mnemonic language is known in advance it'll be better to specify it at construction.

**Code example**

    from bip_utils import (
        Bip39ChecksumError, Bip39Languages, Bip39WordsNum, Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39MnemonicDecoder
    )

    # Mnemonic can be generated with Bip39MnemonicGenerator
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_15)
    # Or it can be a string
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    # Get if a mnemonic is valid, return bool
    is_valid = Bip39MnemonicValidator().IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        Bip39MnemonicValidator().Validate(mnemonic)
        # Valid...
    except Bip39ChecksumError:
        # Invalid checksum...
        pass
    except ValueError:
        # Invalid length or language...
        pass

    # Use Bip39MnemonicDecoder to get back the entropy bytes from a mnemonic, specifying the language
    entropy_bytes = Bip39MnemonicDecoder(Bip39Languages.ENGLISH).Decode(mnemonic)
    # Like before with automatic language detection
    entropy_bytes = Bip39MnemonicDecoder().Decode(mnemonic)

    # Alternatively, it's possible to get back the entropy bytes with the computed checksum
    entropy_chksum_bytes = Bip39MnemonicDecoder(Bip39Languages.ENGLISH).DecodeWithChecksum(mnemonic)

### Seed generation

A secure 64-byte seed is generated from a mnemonic and can be protected by a passphrase.\
This seed can be used to construct a Bip class using the *FromSeed* method (e.g. *Bip44.FromSeed*).\
Also in this case, the language can be specified or automatically detected.

**Code example**

    from bip_utils import Bip39Languages, Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator

    # Mnemonic can be generated with Bip39MnemonicGenerator
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    # Or it can be a string
    mnemonic = "branka dorost klam slanina omezit cuketa kazeta cizost rozchod tvaroh majetek kyvadlo"

    # Generate with automatic language detection and passphrase (empty)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Generate with automatic language detection and custom passphrase
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate("my_passphrase")
    # Generate specifying the language
    seed_bytes = Bip39SeedGenerator(mnemonic, Bip39Languages.CZECH).Generate()

### Substrate seed generation

Polkadot introduced a variant for generating seed, which computes the seed directly from the mnemonic entropy instead of the mnemonic string.\
Reference: [Substrate seed generation](https://wiki.polkadot.network/docs/learn-accounts#seed-generation)\
For this purpose, the class *SubstrateBip39SeedGenerator* can be used, which has the same usage of *Bip39SeedGenerator*.\
The seed can be used to construct a *Substrate* class using the *Substrate.FromSeed* method.

    from bip_utils import Bip39Languages, Bip39WordsNum, Bip39MnemonicGenerator, SubstrateBip39SeedGenerator

    # Mnemonic can be generated with Bip39MnemonicGenerator
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
    # Or it can be a string
    mnemonic = "branka dorost klam slanina omezit cuketa kazeta cizost rozchod tvaroh majetek kyvadlo"

    # Generate with automatic language detection and passphrase (empty)
    seed_bytes = SubstrateBip39SeedGenerator(mnemonic).Generate()
    # Generate with automatic language detection and custom passphrase
    seed_bytes = SubstrateBip39SeedGenerator(mnemonic).Generate("my_passphrase")
    # Generate specifying the language
    seed_bytes = SubstrateBip39SeedGenerator(mnemonic, Bip39Languages.CZECH).Generate()

Please note that this is not used by all wallets supporting Polkadot. For example, TrustWallet or Ledger still use the standard BIP39 seed generation for Polkadot.

## Monero mnemonic library

If you use the official Monero wallet, you'll probably notice that Monero generates mnemonic in its own way, which is different from BIP-0039.\
In fact, it uses different words lists (with 1626 words instead of 2048) and a different algorithm for encoding/decoding the mnemonic string.

The functionalities of this library are the same of the BIP-0039 one but with Monero-style mnemonics:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

### Mnemonic generation

A mnemonic phrase can be generated by specifying the words number (in this case a random entropy will be used) or directly by the entropy bytes.

Supported words number:

|Words number|Enum|Description|
|---|---|---|
|12|*MoneroWordsNum.WORDS_NUM_12*|No checksum|
|13|*MoneroWordsNum.WORDS_NUM_13*|Like before with checksum|
|24|*MoneroWordsNum.WORDS_NUM_24*|No checksum|
|25|*MoneroWordsNum.WORDS_NUM_25*|Like before with checksum|

Now, Monero wallets use 25 words (24 is exactly same but without the last checksum word).\
The 12/13 words mnemonic was an old format used by MyMonero. It's supported only for compatibility but it's not suggested to use mnemonics with those lengths.

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|128|*MoneroEntropyBitLen.BIT_LEN_128*|
|256|*MoneroEntropyBitLen.BIT_LEN_256*|

Supported languages:

|Language|Enum|
|---|---|
|Chinese (simplified)|*MoneroLanguages.CHINESE_SIMPLIFIED*|
|Dutch|*MoneroLanguages.DUTCH*|
|English|*MoneroLanguages.ENGLISH*|
|French|*MoneroLanguages.FRENCH*|
|German|*MoneroLanguages.GERMAN*|
|Italian|*MoneroLanguages.ITALIAN*|
|Japanese|*MoneroLanguages.JAPANESE*|
|Portuguese|*MoneroLanguages.PORTUGUESE*|
|Spanish|*MoneroLanguages.SPANISH*|
|Russian|*MoneroLanguages.RUSSIAN*|

**Code example**

    import binascii
    from bip_utils import MoneroEntropyBitLen, MoneroEntropyGenerator, MoneroMnemonicGenerator, MoneroWordsNum, MoneroLanguages

    # Generate a random mnemonic string of 25 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)

    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())

    # Generate a random mnemonic string of 13 words by specifying the language
    mnemonic = MoneroMnemonicGenerator(MoneroLanguages.ITALIAN).FromWordsNumber(MoneroWordsNum.WORDS_NUM_13)

    # Generate the mnemonic string from entropy bytes
    entropy_bytes = binascii.unhexlify(b"00000000000000000000000000000000")
    mnemonic = MoneroMnemonicGenerator().FromEntropyNoChecksum(entropy_bytes)
    mnemonic = MoneroMnemonicGenerator(MoneroLanguages.FRENCH).FromEntropyWithChecksum(entropy_bytes)

    # Generate mnemonic from random 256-bit entropy (with and without checksum)
    entropy_bytes = MoneroEntropyGenerator(MoneroEntropyBitLen.BIT_LEN_256).Generate()
    mnemonic = MoneroMnemonicGenerator().FromEntropyNoChecksum(entropy_bytes)
    mnemonic = MoneroMnemonicGenerator().FromEntropyWithChecksum(entropy_bytes)

### Mnemonic validation

A mnemonic string can be validated by verifying its language and checksum (if present). Moreover, it is also possible to get back the entropy bytes from a mnemonic.\
When validating, the language can be either specified or automatically detected.\
Automatic detection takes more time, so if the mnemonic language is known in advance it'll be better to specify it at construction.

**Code example**

    from bip_utils import (
        MoneroChecksumError, MoneroLanguages, MoneroWordsNum, MoneroMnemonicGenerator, MoneroMnemonicValidator, MoneroMnemonicDecoder
    )

    # Mnemonic can be generated with MoneroMnemonicGenerator
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "calamity atlas buzzer tyrant natural bumper taboo nozzle puck obtains acoustic aphid decay jittery evicted cuddled love educated koala puddle tarnished necklace anvil axis calamity"

    # Get if a mnemonic is valid, return bool
    is_valid = MoneroMnemonicValidator().IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        MoneroMnemonicValidator().Validate(mnemonic)
        # Valid...
    except MoneroChecksumError:
        # Invalid checksum...
        pass
    except ValueError:
        # Invalid length or language...
        pass

    # Use MoneroMnemonicDecoder to get back the entropy bytes from a mnemonic, specifying the language
    entropy_bytes = MoneroMnemonicDecoder(MoneroLanguages.ENGLISH).Decode(mnemonic)
    # Like before with automatic language detection
    entropy_bytes = MoneroMnemonicDecoder().Decode(mnemonic)

### Seed generation

A seed is generated from a mnemonic and can be used to construct a *Monero* class using the *Monero.FromSeed* method.\
Please note that it's not possible to use a passphrase like BIP-0039.\
Also in this case, the language can be specified or automatically detected.

**Code example**

    from bip_utils import MoneroLanguages, MoneroWordsNum, MoneroMnemonicGenerator, MoneroSeedGenerator

    # Mnemonic can be generated with MoneroMnemonicGenerator
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "fianza dedo mosca bufón bello amable amigo lamer narrar elixir mejilla peine libertad payaso orgullo obtener ganga morder editor orilla gen ocre abuelo anemia editor"

    # Generate with automatic language detection and passphrase (empty)
    seed_bytes = MoneroSeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = MoneroSeedGenerator(mnemonic, MoneroLanguages.SPANISH).Generate()

## BIP-0032 library

The BIP-0032 library allows deriving children keys as defined by [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md).

Since this library is wrapped inside the BIP-0044, BIP-0049 and BIP-0084 libraries, there is no need to use it alone unless you need to derive some non-standard paths.\
The library currently supports the following elliptic curves for key derivation, each one is implemented by a specific class:
- Ed25519 (based on SLIP-0010): *Bip32Ed25519Slip* class
- Ed25519-Blake2b (based on SLIP-0010): *Bip32Ed25519Blake2bSlip* class
- Nist256p1 (based on SLIP-0010): *Bip32Nist256p1* class
- Secp256k1: *Bip32Secp256k1* class

They all inherit from the generic *Bip32Base* class, which can be extended to implement new elliptic curves derivation.\
The curve depends on the specific coin and it's automatically selected if you use the *Bip44* library.

### Construction from seed

The class can be constructed from a seed. The seed can be specified manually or generated by *Bip39SeedGenerator*.\
The constructed class is the master path, so printing the private key will result in printing the master key.

**Code example**

    import binascii
    from bip_utils import Bip39SeedGenerator, Bip32Secp256k1

    # Generate from mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Specify seed manually
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Construct from seed. In case it's a test net, pass True as second parameter. Derivation path returned: m
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
    # Print master key in extended format
    print(bip32_ctx.PrivateKey().ToExtended())

In addition to a seed, it's also possible to specify a derivation path.

**Code example**

    import binascii
    from bip_utils import Bip32Secp256k1

    # Derivation path returned: m/0'/1'/2
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    bip32_ctx = Bip32Secp256k1.FromSeedAndPath(seed_bytes, "m/0'/1'/2")
    # Print private key for derivation path m/0'/1'/2 in extended format
    print(bip32_ctx.PrivateKey().ToExtended())

### Construction from extended key

The class can be constructed directly from an extended key.\
The returned object will be at the same depth of the specified key.

**Code example**

    from bip_utils import Bip32Secp256k1

    # Private extended key from derivation path m/0'/1 (depth 2)
    key_str = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    # Construct from key (return object has depth 2)
    bip32_ctx = Bip32Secp256k1.FromExtendedKey(key_str)
    # Return false
    print(bip32_ctx.IsPublicOnly())
    # Print keys
    print(bip32_ctx.PrivateKey().ToExtended())
    print(bip32_ctx.PublicKey().ToExtended())

    # Public extended key from derivation path m/0'/1 (depth 2)
    key_str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    # Construct from key (return object has depth 2)
    # The object will be public-only and support only public derivation
    bip32_ctx = Bip32Secp256k1.FromExtendedKey(key_str)
    # Return true
    print(bip32_ctx.IsPublicOnly())
    # Print public key
    print(bip32_ctx.PublicKey().ToExtended())

### Construction from private key

The class can be constructed directly from a private key. The key will be considered a master key since there is no way to recover the key derivation data from the key bytes.\
Therefore, the returned object will have a depth equal to zero, a zero chain code and parent fingerprint.

**Code example**

    import binascii
    from bip_utils import Bip32Secp256k1, Secp256k1PrivateKey

    # Construct from private key bytes
    priv_key_bytes = binascii.unhexlify(b"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    bip32_ctx = Bip32Secp256k1.FromPrivateKey(priv_key_bytes)
    # Or key object directly (the curve shall match the one of the Bip32 class, otherwise a Bip32KeyError will be raised)
    bip32_ctx = Bip32Secp256k1.FromPrivateKey(Secp256k1PrivateKey.FromBytes(priv_key_bytes))
    # Print keys and data
    print(bip32_ctx.PrivateKey().Raw().ToHex())
    print(bip32_ctx.PublicKey().RawCompressed().ToHex())
    print(bip32_ctx.Depth().ToInt())
    print(bip32_ctx.ChainCode().ToBytes())
    print(bip32_ctx.ParentFingerPrint().ToBytes())

### Construction from public key

The class can be constructed directly from a public key. The key will be considered a master key since there is no way to recover the key derivation data from the key bytes.\
Therefore, the returned object will have a depth equal to zero, a zero chain code and parent fingerprint.\
The constructed class will be a public-only object (see the example in the next paragraph), so it won't support hardened derivation.

**Code example**

    import binascii
    from bip_utils import Bip32KeyError, Bip32Secp256k1, Secp256k1PublicKey

    # Construct from public key bytes
    pub_key_bytes = binascii.unhexlify(b"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
    bip32_ctx = Bip32Secp256k1.FromPublicKey(pub_key_bytes)
    # Or key object directly (the curve shall match the one of the Bip32 class, otherwise a Bip32KeyError will be raised)
    bip32_ctx = Bip32Secp256k1.FromPublicKey(Secp256k1PublicKey.FromBytes(pub_key_bytes))
    # Print keys and data
    print(bip32_ctx.PublicKey().RawCompressed().ToHex())
    print(bip32_ctx.Depth().ToInt())
    print(bip32_ctx.ChainCode().ToBytes())
    print(bip32_ctx.ParentFingerPrint().ToBytes())

    # Return true
    print(bip32_ctx.IsPublicOnly())
    # Getting the private key will raise a Bip32KeyError
    try:
        print(bip32_ctx.PrivateKey().Raw().ToHex())
    except Bip32KeyError as ex:
        print(ex)

### Keys derivation

Each time a key is derived, a new instance of the class is returned. This allows to chain the methods call or save a specific key pair for future derivation.\
The *Bip32Utils.HardenIndex* method can be used to make an index hardened.

**Code example**

    import binascii
    from bip_utils import Bip32Secp256k1, Bip32Utils

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Path: m
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
    # Derivation path: m/0'/1'/2/3
    bip32_ctx = bip32_ctx.ChildKey(Bip32Utils.HardenIndex(0)) \
                         .ChildKey(Bip32Utils.HardenIndex(1)) \
                         .ChildKey(2)                         \
                         .ChildKey(3)
    # Print keys in extended format
    print(bip32_ctx.PrivateKey().ToExtended())
    print(bip32_ctx.PublicKey().ToExtended())

    # Print keys bytes
    print(bip32_ctx.PrivateKey().Raw().ToBytes())
    print(bytes(bip32_ctx.PrivateKey().Raw()))
    print(bip32_ctx.PublicKey().RawCompressed().ToBytes())
    print(bytes(bip32_ctx.PublicKey().RawCompressed()))
    print(bip32_ctx.PublicKey().RawUncompressed().ToBytes())
    print(bytes(bip32_ctx.PublicKey().RawUncompressed()))

    # Print keys in hex format
    print(bip32_ctx.PrivateKey().Raw().ToHex())
    print(str(bip32_ctx.PrivateKey().Raw()))
    print(bip32_ctx.PublicKey().RawCompressed().ToHex())
    print(str(bip32_ctx.PublicKey().RawCompressed()))
    print(bip32_ctx.PublicKey().RawUncompressed().ToHex())
    print(str(bip32_ctx.PublicKey().RawUncompressed()))

    # Print other BIP32 data
    print(bip32_ctx.Index().IsHardened())
    print(bip32_ctx.Index().ToInt())
    print(int(bip32_ctx.Index()))
    print(bip32_ctx.Index().ToBytes())
    print(bytes(bip32_ctx.Index()))

    print(bip32_ctx.Depth().ToInt())
    print(int(bip32_ctx.Depth()))
    print(bip32_ctx.Depth().ToBytes())
    print(bytes(bip32_ctx.Depth()))

    print(bip32_ctx.ChainCode().ToHex())
    print(str(bip32_ctx.ChainCode()))
    print(bip32_ctx.ChainCode().ToBytes())
    print(bytes(bip32_ctx.ChainCode()))

    print(bip32_ctx.FingerPrint().IsMasterKey())
    print(str(bip32_ctx.FingerPrint()))
    print(bip32_ctx.FingerPrint().ToBytes())
    print(bytes(bip32_ctx.FingerPrint()))

    print(bip32_ctx.ParentFingerPrint().IsMasterKey())
    print(bip32_ctx.ParentFingerPrint().ToBytes())
    print(bytes(bip32_ctx.ParentFingerPrint()))

    # Alternative: use DerivePath method
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
    bip32_ctx = bip32_ctx.DerivePath("0'/1'/2/3")

    # DerivePath derives from the current depth, so it can be split
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
    bip32_ctx = bip32_ctx.DerivePath("0'/1'")   # Derivation path: m/0'/1'
    bip32_ctx = bip32_ctx.DerivePath("2/3")     # Derivation path: m/0'/1'/2/3

It's also possible to use public derivation (i.e. "watch-only" addresses) by:
- converting a private object to a public-only using *ConvertToPublic* method
- constructing a public-only object from a public key

In case of a public-only object, only public derivation will be supported (only not-hardened indexes), otherwise a Bip32KeyError exception will be raised.

**Code example**

    from bip_utils import Bip32KeyError, Bip32Utils, Bip32Secp256k1

    # Derive from a public extended key
    key_str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    bip32_ctx = Bip32Secp256k1.FromExtendedKey(key_str)

    # Return true
    print(bip32_ctx.IsPublicOnly())
    # Print public key
    print(bip32_ctx.PublicKey().RawCompressed().ToHex())

    # Public derivation is used to derive a child key
    bip32_ctx = bip32_ctx.ChildKey(0)
    bip32_ctx = bip32_ctx.DerivePath("1/2")
    # Print key
    print(bip32_ctx.PublicKey().RawCompressed().ToHex())

    # Getting the private key will raise a Bip32KeyError
    try:
        print(bip32_ctx.PrivateKey().Raw().ToHex())
    except Bip32KeyError as ex:
        print(ex)

    # Deriving with hardened indexes will raise a Bip32KeyError
    try:
        bip32_ctx = bip32_ctx.ChildKey(Bip32Utils.HardenIndex(0))
        bip32_ctx = bip32_ctx.DerivePath("1'/2")
    except Bip32KeyError as ex:
        print(ex)

    # Derive from a private extended key
    key_str = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    bip32_ctx = Bip32Secp256k1.FromExtendedKey(key_str)
    # Convert to public object
    bip32_ctx.ConvertToPublic()
    # Same as before...

The other BIP32 classes work exactly in the same way.\
However, the *Bip32Ed25519Slip* and *Bip32Ed25519Blake2bSlip* classes have some differences (as written in SLIP-0010):
- Not-hardened private key derivation is not supported
- Public key derivation is not supported

For example:

    import binascii
    from bip_utils import Bip32KeyError, Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Only hardened private key derivation, fine
    bip32_ctx = Bip32Ed25519Slip.FromSeedAndPath(seed_bytes, "m/0'/1'")

    # Public derivation, Bip32KeyError is raised
    try:
        bip32_ctx = Bip32Ed25519Slip.FromSeedAndPath(seed_bytes, "m/0'/1'")
        bip32_ctx.ConvertToPublic()
        bip32_ctx.ChildKey(0)
    except Bip32KeyError as ex:
        print(ex)

    # Same as before
    try:
        bip32_ctx = Bip32Ed25519Blake2bSlip.FromSeedAndPath(seed_bytes, "m/0'/1'")
        bip32_ctx.ConvertToPublic()
        bip32_ctx.ChildKey(0)
    except Bip32KeyError as ex:
        print(ex)

    # Not-hardened private key derivation, Bip32KeyError is raised
    try:
        bip32_ctx = Bip32Ed25519Slip.FromSeedAndPath(seed_bytes, "m/0/1")
        bip32_ctx = Bip32Ed25519Blake2bSlip.FromSeedAndPath(seed_bytes, "m/0/1")
    except Bip32KeyError as ex:
        print(ex)

### Parse path

The Bip32 module allows also to parse derivation paths.

**Code example**

    from bip_utils import Bip32Path, Bip32PathParser, Bip32Utils

    # Parse path, Bip32PathError is raised in case of errors
    path = Bip32PathParser.Parse("0'/1'/2")
    # 'p' can be used as an alternative character instead of '
    path = Bip32PathParser.Parse("0p/1p/2")
    # "m" can be added at the beginning
    path = Bip32PathParser.Parse("m/0'/1'/2")
    # Or construct directly from a list of indexes
    path = Bip32Path([0, 1, Bip32Utils.HardenIndex(2)])

    # Get length
    print(path.Length())
    # Get as string
    print(path.ToStr())
    print(str(path))
    # Print elements info and value
    for elem in path:
        print(elem.IsHardened())
        print(elem.ToBytes())
        print(bytes(elem))
        print(elem.ToInt())
        print(int(elem))
    # Get as list of integers
    path_list = path.ToList()
    for elem in path_list:
        print(elem)

## BIP-0044, BIP-0049, BIP-0084 libraries

The BIP-0044, BIP-0049 and BIP-0084 libraries allows deriving a hierarchy of keys as defined by [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-0049](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) and [BIP-0084](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki).

They internally use the BIP-0032 classes for keys derivation, selecting the correct one depending on the elliptic curve of the specific coin.

### Coin types

#### BIP-0044

Supported coins enumerative for BIP-0044:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Algorand|*Bip44Coins.ALGORAND*|-|
|Avalanche C-Chain|*Bip44Coins.AVAX_C_CHAIN*|-|
|Avalanche P-Chain|*Bip44Coins.AVAX_P_CHAIN*|-|
|Avalanche X-Chain|*Bip44Coins.AVAX_X_CHAIN*|-|
|Band Protocol|*Bip44Coins.BAND_PROTOCOL*|-|
|Binance Chain|*Bip44Coins.BINANCE_CHAIN*|-|
|Binance Smart Chain|*Bip44Coins.BINANCE_SMART_CHAIN*|-|
|Bitcoin|*Bip44Coins.BITCOIN*|*Bip44Coins.BITCOIN_TESTNET*|
|Bitcoin Cash|*Bip44Coins.BITCOIN_CASH*|*Bip44Coins.BITCOIN_CASH_TESTNET*|
|BitcoinSV|*Bip44Coins.BITCOIN_SV*|*Bip44Coins.BITCOIN_SV_TESTNET*|
|Cosmos|*Bip44Coins.COSMOS*|-|
|Dash|*Bip44Coins.DASH*|*Bip44Coins.DASH_TESTNET*|
|Dogecoin|*Bip44Coins.DOGECOIN*|*Bip44Coins.DOGECOIN_TESTNET*|
|Elrond|*Bip44Coins.ELROND*|-|
|EOS|*Bip44Coins.EOS*|-|
|Ethereum|*Bip44Coins.ETHEREUM*|-|
|Ethereum Classic|*Bip44Coins.ETHEREUM_CLASSIC*|-|
|Fantom Opera|*Bip44Coins.FANTOM_OPERA*|-|
|Filecoin|*Bip44Coins.FILECOIN*|-|
|Harmony One (Cosmos address)|*Bip44Coins.HARMONY_ONE_ATOM*|-|
|Harmony One (Ethereum address)|*Bip44Coins.HARMONY_ONE_ETH*|-|
|Harmony One (Metamask address)|*Bip44Coins.HARMONY_ONE_METAMASK*|-|
|Huobi Chain|*Bip44Coins.HUOBI_CHAIN*|-|
|IRIS Network|*Bip44Coins.IRIS_NET*|-|
|Kava|*Bip44Coins.KAVA*|-|
|Kusama (ed25519 SLIP-0010)|*Bip44Coins.KUSAMA_ED25519_SLIP*|-|
|Litecoin|*Bip44Coins.LITECOIN*|*Bip44Coins.LITECOIN_TESTNET*|
|Monero (ed25519 SLIP-0010, please see the Monero paragraph below)|*Bip44Coins.MONERO_ED25519_SLIP*|-|
|Monero (secp256k1, please see the Monero paragraph below)|*Bip44Coins.MONERO_SECP256K1*|-|
|Nano|*Bip44Coins.NANO*|-|
|NEO|*Bip44Coins.NEO*|-|
|OKEx Chain (Cosmos address)|*Bip44Coins.OKEX_CHAIN_ATOM*|-|
|OKEx Chain (Ethereum address)|*Bip44Coins.OKEX_CHAIN_ETH*|-|
|OKEx Chain (Old Cosmos address before mainnet upgrade)|*Bip44Coins.OKEX_CHAIN_ATOM_OLD*|-|
|Ontology|*Bip44Coins.ONTOLOGY*|-|
|Polkadot (ed25519 SLIP-0010)|*Bip44Coins.POLKADOT_ED25519_SLIP*|-|
|Polygon|*Bip44Coins.POLYGON*|-|
|Ripple|*Bip44Coins.RIPPLE*|-|
|Solana|*Bip44Coins.SOLANA*|-|
|Stellar|*Bip44Coins.STELLAR*|-|
|Terra|*Bip44Coins.TERRA*|-|
|Tezos|*Bip44Coins.TEZOS*|-|
|Theta Network|*Bip44Coins.THETA*|-|
|Tron|*Bip44Coins.TRON*|-|
|VeChain|*Bip44Coins.VECHAIN*|-|
|Zcash|*Bip44Coins.ZCASH*|*Bip44Coins.ZCASH_TESTNET*|
|Zilliqa|*Bip44Coins.ZILLIQA*|-|

The code is structured so that it can be easily extended with other coins if needed (provided that the coin elliptic curve is supported).

**NOTES**

- *Bip44Coins.HARMONY_ONE_ETH* generates the address using the Harmony One coin index (i.e. *1023*).
This is the behavior of the official Harmony One wallet and the Ethereum address that you get in the Harmony One explorer.\
  However, if you just add the Harmony One network in Metamask, Metamask will use the Ethereum coin index (i.e. *60*) thus resulting in a different address.
Therefore, if you need to generate the Harmony One address for Metamask, use *Bip44Coins.HARMONY_ONE_METAMASK*.
- *Bip44Coins.OKEX_CHAIN_ETH* and *Bip44Coins.OKEX_CHAIN_ATOM* generate the address using the Ethereum coin index (i.e. *60*).
These formats are the ones used by the OKEx wallet. *Bip44Coins.OKEX_CHAIN_ETH* is compatible with Metamask.\
*Bip44Coins.OKEX_CHAIN_ATOM_OLD* generates the address using the OKEx Chain coin index (i.e. *996*).
  This address format was used before the mainnet upgrade (some wallets still use it, e.g. Cosmostation).

#### BIP-0049

Supported coins enumerative for BIP-0049:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin|*Bip49Coins.BITCOIN*|*Bip49Coins.BITCOIN_TESTNET*|
|Bitcoin Cash|*Bip49Coins.BITCOIN_CASH*|*Bip49Coins.BITCOIN_CASH_TESTNET*|
|BitcoinSV|*Bip49Coins.BITCOIN_SV*|*Bip49Coins.BITCOIN_SV_TESTNET*|
|Dash|*Bip49Coins.DASH*|*Bip49Coins.DASH_TESTNET*|
|Dogecoin|*Bip49Coins.DOGECOIN*|*Bip49Coins.DOGECOIN_TESTNET*|
|Litecoin|*Bip49Coins.LITECOIN*|*Bip49Coins.LITECOIN_TESTNET*|
|Zcash|*Bip49Coins.ZCASH*|*Bip49Coins.ZCASH_TESTNET*|

#### BIP-0084

Supported coins enumerative for BIP-0084:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin|*Bip84Coins.BITCOIN*|*Bip84Coins.BITCOIN_TESTNET*|
|Litecoin|*Bip84Coins.LITECOIN*|*Bip84Coins.LITECOIN_TESTNET*|

### Construction from seed

A Bip class can be constructed from a seed, like *Bip32*. The seed can be specified manually or generated by *Bip39SeedGenerator*.

**Code example**

    import binascii
    from bip_utils import Bip39SeedGenerator, Bip44Coins, Bip44

    # Generate from mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Specify seed manually
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Derivation path returned: m
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

### Construction from extended key

A Bip class can be constructed directly from an extended key.\
The returned Bip object will be at the same depth of the specified key. If the depth of the key is not valid, a *Bip44DepthError* exception will be raised.

**Code example**

    from bip_utils import Bip44Coins, Bip44

    # Private extended key
    key_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    # Construct from extended key
    bip44_mst_ctx = Bip44.FromExtendedKey(key_str, Bip44Coins.BITCOIN)

### Construction from private key

A Bip class can be constructed directly from a private key. Like *Bip32*, the key will be considered a master key since there is no way to recover the key derivation data from the key bytes.\
Therefore, the returned object will have a depth equal to zero, a zero chain code and parent fingerprint.

**Code example**

    import binascii
    from bip_utils import Bip44Coins, Bip44, Secp256k1PrivateKey

    # Construct from private key bytes
    priv_key_bytes = binascii.unhexlify(b"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    bip44_mst_ctx = Bip44.FromPrivateKey(priv_key_bytes, Bip44Coins.BITCOIN)
    # Or key object directly (the key type shall match the curve used by the coin, otherwise Bip32KeyError will be raised)
    bip44_mst_ctx = Bip44.FromPrivateKey(Secp256k1PrivateKey.FromBytes(priv_key_bytes), Bip44Coins.BITCOIN)

### Keys derivation

Like *Bip32*, each time a key is derived a new instance of the Bip class is returned.\
The keys must be derived with the levels specified by BIP-0044:

    m / purpose' / coin_type' / account' / change / address_index

using the correspondent methods. If keys are derived in the wrong level, a *Bip44DepthError* will be raised.\
The private and public extended keys can be printed at any level.

**NOTE**: In case not-hardened private derivation is not supported (e.g. in ed25519 SLIP-0010), all indexes will be hardened:

    m / purpose' / coin_type' / account' / change' / address_index'

**Code example**

    import binascii
    from bip_utils import Bip44Changes, Bip44Coins, Bip44Levels, Bip44

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Create from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

    # Print master key in extended format
    print(bip44_mst_ctx.PrivateKey().ToExtended())
    # Print master key in hex format
    print(bip44_mst_ctx.PrivateKey().Raw().ToHex())

    # Print public key in extended format
    print(bip44_mst_ctx.PublicKey().ToExtended())
    # Print public key in raw uncompressed format
    print(bip44_mst_ctx.PublicKey().RawUncompressed().ToHex())
    # Print public key in raw compressed format
    print(bip44_mst_ctx.PublicKey().RawCompressed().ToHex())

    # Print the master key in WIF
    print(bip44_mst_ctx.IsLevel(Bip44Levels.MASTER))
    print(bip44_mst_ctx.PrivateKey().ToWif())

    # Derive account 0 for Bitcoin: m/44'/0'/0'
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    # Print keys in extended format
    print(bip44_acc_ctx.IsLevel(Bip44Levels.ACCOUNT))
    print(bip44_acc_ctx.PrivateKey().ToExtended())
    print(bip44_acc_ctx.PublicKey().ToExtended())
    # Address of account level
    print(bip44_acc_ctx.PublicKey().ToAddress())

    # Derive the external chain: m/44'/0'/0'/0
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    # Print again keys in extended format
    print(bip44_chg_ctx.IsLevel(Bip44Levels.CHANGE))
    print(bip44_chg_ctx.PrivateKey().ToExtended())
    print(bip44_chg_ctx.PublicKey().ToExtended())
    # Address of change level
    print(bip44_chg_ctx.PublicKey().ToAddress())

    # Derive the first 20 addresses of the external chain: m/44'/0'/0'/0/i
    for i in range(20):
        bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)

        print(bip44_addr_ctx.IsLevel(Bip44Levels.ADDRESS_INDEX))
        # Print extended keys and address
        print(bip44_addr_ctx.PrivateKey().ToExtended())
        print(bip44_addr_ctx.PublicKey().ToExtended())
        print(bip44_addr_ctx.PublicKey().ToAddress())

**NOTE:** since all the classes derive from the same base class, their usage is the same. Therefore, in all the code examples *Bip44* can be substituted by *Bip49* or *Bip84* without changing the code.

### Default derivation paths

Most of the coins (especially the ones using the secp256k1 curve) use the complete BIP-0044 path to derive the address private key:

    m / purpose' / coin_type' / account' / change / address_index

However, this doesn't apply all coins. For example, Solana uses the following path to derive the address private key: m/44'/501'/0'\
This can be derived manually, for example:

    import binascii
    from bip_utils import Bip44Coins, Bip44

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Derive m/44'/501'/0'
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    # Default address generated by the wallet (e.g. TrustWallet): m/44'/501'/0'
    print(bip44_acc_ctx.PublicKey().ToAddress())

However, in order to avoid remembering the default path for each coin, the *DeriveDefaultPath* method can be used to automatically derive the default path:

    import binascii
    from bip_utils import Bip44Coins, Bip44

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Automatically derive m/44'/501'/0'
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA).DeriveDefaultPath()
    # Same as before
    print(bip44_def_ctx.PublicKey().ToAddress())

    # Automatically derive m/44'/3'/0'/0/0
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.DOGECOIN).DeriveDefaultPath()
    # Same as before
    print(bip44_def_ctx.PublicKey().ToAddress())

### Polkadot/Kusama addresses generation

Polkadot and Kusama don't support BIP44, so if you use them through the *Bip44* class you're basically "forcing" them to follow it. Therefore, keys and addresses generated in this way will be different from the official Polkadot wallet.\
For this, I used the same implementation of TrustWallet, i.e.:
- The derivation scheme is based on ed25519 SLIP-0010
- The default derivation path is: m/44'/354'/0'/0'/0'

If you want to get the same keys and addresses of the Polkadot-JS wallet, use the *Substrate* module (see the related paragraph).

### Monero addresses generation

Monero works differently from other coins, because it has 2 private keys and 2 public keys (one for spending, one for viewing).\
Moreover, it has its own algorithm to generate the so-called "subaddresses", which have nothing to do with the addresses derived at the "address" level in BIP44.\
Therefore, Monero shall be treated separately to get keys and addresses by using the *Monero* module.

Like Polkadot/Kusama in the previous paragraph, Monero doesn't support BIP44 so if you use it through the *Bip44* class you're basically "forcing" Monero to follow it.\
Since there is no specification that states how to implement Monero using BIP44, I look a little bit around and I created two implementations:
- *Bip44Coins.MONERO_ED25519_SLIP* uses the ed25519 curve (like Monero itself) with the SLIP-0010 derivation scheme and the default derivation path is m/44'/128'/0'/0'/0'
- *Bip44Coins.MONERO_SECP256K1* uses the secp256k1 curve (like Bitcoin) and the default derivation path is m/44'/128'/0'/0/0 (like the Ledger implementation)

Of course, you are free to derive other paths if you want.\
Whatever implementation or path you choose, the Monero private spend key is computed from the *Bip44* private key as follows:
- perform keccak256 of the key bytes
- apply *sc_reduce* to the result to get a valid Monero private key

**Code example**

    import binascii
    from bip_utils import Bip44Coins, Bip44, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Create BIP44 object and derive default path
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP).DeriveDefaultPath()

    # Create Monero object from the BIP44 private key -> monero_priv_spend_key = sc_reduce(kekkak256(bip44_priv_key))
    monero = Monero.FromBip44PrivateKey(bip44_def_ctx.PrivateKey().Raw().ToBytes())

    # Print keys
    print(monero.PrivateSpendKey().Raw().ToHex())
    print(monero.PrivateViewKey().Raw().ToHex())
    print(monero.PublicSpendKey().RawCompressed().ToHex())
    print(monero.PublicViewKey().RawCompressed().ToHex())

    # Print primary address
    print(monero.PrimaryAddress())
    # Print subaddresses
    print(monero.Subaddress(0))         # Account 0 (default), Subaddress 0 (same as primary address)
    print(monero.Subaddress(1))         # Account 0 (default), Subaddress 1
    print(monero.Subaddress(0, 1))      # Account 1, Subaddress 0
    print(monero.Subaddress(1, 1))      # Account 1, Subaddress 1

If you prefer not to perform the kekkak256 of the key bytes, you can just use the *Bip44* private key directly as a Monero seed:

**Code example**

    import binascii
    from bip_utils import Bip44Coins, Bip44, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Create BIP44 object and derive default path
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP).DeriveDefaultPath()

    # Create Monero object using the BIP44 private key as seed -> monero_priv_spend_key = sc_reduce(bip44_priv_key)
    monero = Monero.FromSeed(bip44_def_ctx.PrivateKey().Raw().ToBytes())
    # Same as before...

Please note that, if the seed is generated from a Monero mnemonic phrase, you'll get the same keys and addresses of the official Monero wallets.\
For the usage of the *Monero* module alone, see the related paragraph.

## Substrate library

The Substrate library allows to [derive keys](https://wiki.polkadot.network/docs/learn-accounts#derivation-paths) for coins of the Polkadot ecosystem, since they don't follow BIP44.\
The module generates the same keys and addresses of Polkadot-JS and uses sr25519 curve for keys derivation.\
With respect to BIP-0032, Substrate paths can be also strings (in addition to numbers) and they are identified by a prefix:
- "/" for not-hardened (soft) derivation (e.g. "/soft")
- "//" for hardened derivation (e.g. "//hard")

### Coin types

Supported coins enumerative:

|Coin|Enum|
|---|---|
|Acala|*SubstrateCoins.ACALA*|
|Bifrost|*SubstrateCoins.BIFROST*|
|Chainx|*SubstrateCoins.CHAINX*|
|Edgeware|*SubstrateCoins.EDGEWARE*|
|Generic|*SubstrateCoins.GENERIC*|
|Karura|*SubstrateCoins.KARURA*|
|Kusama|*SubstrateCoins.KUSAMA*|
|Moonbeam|*SubstrateCoins.MOONBEAM*|
|Moonriver|*SubstrateCoins.MOONRIVER*|
|Phala Network|*SubstrateCoins.PHALA*|
|Plasm Network|*SubstrateCoins.PLASM*|
|Polkadot|*SubstrateCoins.POLKADOT*|
|Sora|*SubstrateCoins.SORA*|
|Stafi|*SubstrateCoins.STAFI*|

The code is structured so that it can be easily extended with other coins if needed.

### Construction from seed

The class can be constructed from a seed, like *Bip32*. The seed can be specified manually or generated by *SubstrateBip39SeedGenerator*.

**NOTE**: If *Bip39SeedGenerator* is used instead, the wrong addresses will be generated

**Code example**

    import binascii
    from bip_utils import SubstrateBip39SeedGenerator, SubstrateCoins, Substrate

    # Generate from mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = SubstrateBip39SeedGenerator(mnemonic).Generate()
    # Specify seed manually. The seed is required to be 32-byte long. If longer, only the first 32-byte will be considered.
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1")

    # Construction from seed
    substrate_ctx = Substrate.FromSeed(seed_bytes, SubstrateCoins.POLKADOT)
    # Construction from seed by specifying the path
    substrate_ctx = Substrate.FromSeedAndPath(seed_bytes, "//hard/soft", SubstrateCoins.POLKADOT)

### Construction from private/public key

The class can be constructed from a private or a public key.

**Code example**

    import binascii
    from bip_utils import SubstrateCoins, Substrate, Sr25519PublicKey, Sr25519PrivateKey

    # Construction from private key bytes
    priv_key_bytes = binascii.unhexlify(b"2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8")
    substrate_ctx = Substrate.FromPrivateKey(priv_key_bytes, SubstrateCoins.POLKADOT)
    # Or key object directly
    substrate_ctx = Substrate.FromPrivateKey(Sr25519PrivateKey.FromBytes(priv_key_bytes), SubstrateCoins.POLKADOT)
    # Return false
    print(substrate_ctx.IsPublicOnly())

    # Construction from public key bytes
    # The object will be public-only and support only public derivation
    pub_key_bytes = binascii.unhexlify(b"66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972")
    substrate_ctx = Substrate.FromPublicKey(pub_key_bytes, SubstrateCoins.POLKADOT)
    # Or key object directly
    substrate_ctx = Substrate.FromPublicKey(Sr25519PublicKey.FromBytes(pub_key_bytes), SubstrateCoins.POLKADOT)
    # Return true
    print(substrate_ctx.IsPublicOnly())

### Keys derivation

Like *Bip32*, each time a key is derived a new instance of the Substrate class is returned.\
The usage is similar to *Bip32*/*Bip44* module.

**Code example**

    import binascii
    from bip_utils import SubstrateCoins, Substrate

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1")
    # Construction from seed
    substrate_ctx = Substrate.FromSeed(seed_bytes, SubstrateCoins.POLKADOT)
    # Print master keys and address
    print(substrate_ctx.PrivateKey().Raw().ToBytes())
    print(bytes(substrate_ctx.PrivateKey().Raw()))
    print(substrate_ctx.PrivateKey().Raw().ToHex())
    print(substrate_ctx.PublicKey().RawCompressed().ToBytes())
    print(bytes(substrate_ctx.PublicKey().RawCompressed()))
    print(substrate_ctx.PublicKey().RawCompressed().ToHex())
    print(substrate_ctx.PublicKey().ToAddress())

    # Derive a child key
    substrate_ctx = substrate_ctx.ChildKey("//hard")
    # Print derived keys and address
    print(substrate_ctx.PrivateKey().Raw().ToHex())
    print(substrate_ctx.PublicKey().RawCompressed().ToHex())
    print(substrate_ctx.PublicKey().ToAddress())
    # Print path
    print(substrate_ctx.Path().ToStr())

    # Derive a path
    substrate_ctx = substrate_ctx.DerivePath("//hard/soft") # Path: //hard/soft
    substrate_ctx = substrate_ctx.DerivePath("//0/1")       # Path: //hard/soft//0/1
    # Print derived keys and address
    print(substrate_ctx.PrivateKey().Raw().ToHex())
    print(substrate_ctx.PublicKey().RawCompressed().ToHex())
    print(substrate_ctx.PublicKey().ToAddress())
    # Print path
    print(substrate_ctx.Path().ToStr())

It's also possible to use public derivation (i.e. "watch-only" addresses) by:
- converting a private object to a public-only using *ConvertToPublic* method
- constructing a public-only object from a public key

In case of a public-only object, only public derivation will be supported (only "soft" path elements), otherwise a SubstrateKeyError exception will be raised.

**Code example**

    import binascii
    from bip_utils import SubstrateKeyError, SubstrateCoins, Substrate

    # Construction from public key
    pub_key_bytes = b"66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
    substrate_ctx = Substrate.FromPublicKey(binascii.unhexlify(pub_key_bytes), SubstrateCoins.POLKADOT)
    # Return true
    print(substrate_ctx.IsPublicOnly())
    # Print key and address
    print(substrate_ctx.PublicKey().RawCompressed().ToHex())
    print(substrate_ctx.PublicKey().ToAddress())

    # Public derivation is used to derive a child key
    substrate_ctx = substrate_ctx.ChildKey("/soft")
    # Print key and address
    print(substrate_ctx.PublicKey().RawCompressed().ToHex())
    print(substrate_ctx.PublicKey().ToAddress())
    # Print path
    print(substrate_ctx.Path().ToStr())
    # Public derivation is used to derive a path
    substrate_ctx = substrate_ctx.DerivePath("/0/1")

    # Getting the private key will raise a SubstrateKeyError
    try:
        print(substrate_ctx.PrivateKey().Raw().ToHex())
    except SubstrateKeyError as ex:
        print(ex)

    # Deriving a hard path will raise a SubstrateKeyError
    try:
        substrate_ctx = substrate_ctx.ChildKey("//hard")
        substrate_ctx = substrate_ctx.DerivePath("//0/1")
    except SubstrateKeyError as ex:
        print(ex)

    # Construction from private key
    priv_key_bytes = b"2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8"
    substrate_ctx = Substrate.FromPrivateKey(binascii.unhexlify(priv_key_bytes), SubstrateCoins.POLKADOT)
    # Convert to public object
    substrate_ctx.ConvertToPublic()
    # Same as before...

### Parse path

The Substrate module allows also to parse derivation paths.\
Please note that, if a path contains only numbers (e.g. "//123"), it'll be considered as an integer and not as a string of ASCII characters.

**Code example**

    from bip_utils import SubstratePath, SubstratePathParser

    # Parse path, SubstratePathError is raised in case of errors
    path = SubstratePathParser.Parse("//hard/soft")
    # Or construct directly from a list of indexes
    path = SubstratePath(["//hard", "/soft"])

    # Get length
    print(path.Length())
    # Get as string
    print(path.ToStr())
    print(str(path))
    # Print elements info and value
    for elem in path:
        print(elem.IsHard())
        print(elem.IsSoft())
        print(elem.ToStr())
        print(str(elem))
        print(elem.ChainCode())
    # Get as list of strings
    path_list = path.ToList()
    for elem in path_list:
        print(elem)

## Monero library

The Monero library allows to generate Monero keys, primary address and subaddresses like the official Monero wallets.

### Coin types

Supported coins enumerative:

|Coin|Enum|
|---|---|
|Monero main net|*MoneroCoins.MONERO_MAINNET*|
|Monero stage net|*MoneroCoins.MONERO_STAGENET*|
|Monero test net|*MoneroCoins.MONERO_TESTNET*|

Coin type is passed to all construction methods. The default type is always Monero main net.

### Construction from seed

The class can be constructed from a seed, which is usually computed from the Monero mnemonic phrase.\
In case of a 24/25 words phrase, the seed corresponds to the private spend key. Otherwise, the private spend key will be the kekkak256 of the seed.

**NOTE:** Monero mnemonic phrase generation is currently not supported

**Code example**

    import binascii
    from bip_utils import MoneroCoins, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"851466f170f7d1dd88325d9f6b89328166fa23e3af712e74aa27cb16837ac10d")
    # Create from seed (default: Monero main net)
    monero = Monero.FromSeed(seed_bytes)
    # Return false
    print(monero.IsWatchOnly())

    # Create from seed for Monero stage net
    monero = Monero.FromSeed(seed_bytes, MoneroCoins.MONERO_STAGENET)
    # Create from seed for Monero test net
    monero = Monero.FromSeed(seed_bytes, MoneroCoins.MONERO_TESTNET)

### Construction from private spend key

The class can be constructed directly from the private spend key.

**Code example**

    import binascii
    from bip_utils import MoneroCoins, Monero, Ed25519MoneroPrivateKey

    # Create from private spend key bytes (default: Monero main net)
    key_bytes = binascii.unhexlify(b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107")
    monero = Monero.FromPrivateSpendKey(key_bytes)
    # Or key object directly
    monero = Monero.FromPrivateSpendKey(Ed25519MoneroPrivateKey.FromBytes(key_bytes))
    # Return false
    print(monero.IsWatchOnly())

    # Create from private spend key bytes for Monero test net
    key_bytes = binascii.unhexlify(b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107")
    monero = Monero.FromPrivateSpendKey(key_bytes, MoneroCoins.MONERO_TESTNET)

### Construction from Bip44 private key

The class can be constructed from a *Bip44* private key. Please refer to the related paragraph in the Bip44 chapter.

### Watch-only class

A watch-only class can be constructed from the private view key and the public spend key.

**Code example**

    import binascii
    from bip_utils import MoneroKeyError, MoneroCoins, Monero, Ed25519MoneroPrivateKey, Ed25519MoneroPublicKey

    # Keys
    priv_vkey_bytes = binascii.unhexlify(b"14467d1b9bb8d1fcfb5b7ae08cc9994367e917efd7e08cf94f9882ffa0629e09")
    pub_skey_bytes = binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422")

    # Create from watch-only keys (default: Monero main net)
    monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes)
    # Or key object directly
    monero = Monero.FromWatchOnly(Ed25519MoneroPrivateKey.FromBytes(priv_vkey_bytes),
                                  Ed25519MoneroPublicKey.FromBytes(pub_skey_bytes))
    # Return true
    print(monero.IsWatchOnly())
    # Getting the private spend key will raise a MoneroKeyError
    try:
        print(monero.PrivateSpendKey().Raw().ToHex())
    except MoneroKeyError as ex:
        print(ex)


    # Create from watch-only keys for Monero test net
    monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes, MoneroCoins.MONERO_TESTNET)

### Example of usage

**Code example**

    import binascii
    from bip_utils import Monero

    # Create from seed bytes
    seed_bytes = binascii.unhexlify(b"851466f170f7d1dd88325d9f6b89328166fa23e3af712e74aa27cb16837ac10d")
    monero = Monero.FromSeed(seed_bytes)
    # Print if watch-only
    print(monero.IsWatchOnly())

    # Print keys
    print(monero.PrivateSpendKey().Raw().ToHex())
    print(monero.PrivateSpendKey().Raw().ToBytes())
    print(monero.PrivateViewKey().Raw().ToHex())
    print(monero.PrivateViewKey().Raw().ToBytes())
    print(monero.PublicSpendKey().RawCompressed().ToHex())
    print(monero.PublicSpendKey().RawCompressed().ToBytes())
    print(monero.PublicViewKey().RawCompressed().ToHex())
    print(monero.PublicViewKey().RawCompressed().ToBytes())

    # Print primary address
    print(monero.PrimaryAddress())
    # Print integrated address
    payment_id = binascii.unhexlify(b"ccc172c2ffcac9d8")
    print(monero.IntegratedAddress(payment_id))
    # Print subaddresses
    print(monero.Subaddress(0))         # Account 0 (default), Subaddress 0 (same as primary address)
    print(monero.Subaddress(1))         # Account 0 (default), Subaddress 1
    print(monero.Subaddress(0, 1))      # Account 1, Subaddress 0
    print(monero.Subaddress(1, 1))      # Account 1, Subaddress 1

## Addresses generation

These libraries are used internally by the other libraries, but they are available also for external use.

**Code example**

    import binascii
    from bip_utils import *

    #
    # Addresses that require a secp256k1 curve
    #

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2")
    pub_key = Secp256k1PublicKey.FromBytes(binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2"))

    # P2PKH/P2SH/P2WPKH address with parameters from generic configuration
    addr = P2PKHAddr.EncodeKey(pub_key,
                               net_ver=CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver"))
    addr = P2SHAddr.EncodeKey(pub_key,
                               net_ver=CoinsConf.BitcoinMainNet.Params("p2sh_net_ver"))
    addr = P2WPKHAddr.EncodeKey(pub_key,
                                hrp=CoinsConf.BitcoinMainNet.Params("p2wpkh_hrp"),
                                wit_ver=CoinsConf.BitcoinMainNet.Params("p2wpkh_wit_ver"))
    # Or with custom parameters
    addr = P2PKHAddr.EncodeKey(pub_key,
                               net_ver=b"\x01")
    addr = P2SHAddr.EncodeKey(pub_key,
                               net_ver=b"\x01")
    addr = P2WPKHAddr.EncodeKey(pub_key,
                                hrp="hrp",
                                wit_ver=0)
    # Or simply with the default parameters from BIP:
    addr = P2PKHAddr.EncodeKey(pub_key,
                               **Bip44Conf.BitcoinMainNet.AddrParams())
    addr = P2SHAddr.EncodeKey(pub_key,
                               **Bip49Conf.BitcoinMainNet.AddrParams())
    addr = P2WPKHAddr.EncodeKey(pub_key,
                                **Bip84Conf.BitcoinMainNet.AddrParams())

    # P2PKH/P2SH address in Bitcoin Cash format (net version from configuration)
    addr = BchP2PKHAddr.EncodeKey(pub_key,
                                  hrp=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
                                  net_ver=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"))
    addr = BchP2SHAddr.EncodeKey(pub_key,
                                 hrp=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
                                 net_ver=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"))
    # Or with custom parameters
    addr = BchP2PKHAddr.EncodeKey(pub_key,
                                  hrp="hrp",
                                  net_ver=b"\x01")
    addr = BchP2SHAddr.EncodeKey(pub_key,
                                 hrp="hrp",
                                 net_ver=b"\x01")
    # Or with the default parameters from BIP:
    addr = BchP2PKHAddr.EncodeKey(pub_key,
                                  **Bip44Conf.BitcoinCashMainNet.AddrParams())
    addr = BchP2SHAddr.EncodeKey(pub_key,
                                 **Bip49Conf.BitcoinCashMainNet.AddrParams())

    # Ethereum address
    addr = EthAddr.EncodeKey(pub_key)
    # Tron address
    addr = TrxAddr.EncodeKey(pub_key)
    # AVAX address
    addr = AvaxPChainAddr.EncodeKey(pub_key)
    addr = AvaxXChainAddr.EncodeKey(pub_key)
    # Atom addresses with parameters from generic configuration
    addr = AtomAddr.EncodeKey(pub_key,
                              hrp=CoinsConf.Cosmos.Params("addr_hrp"))
    addr = AtomAddr.EncodeKey(pub_key,
                              hrp=CoinsConf.BinanceChain.Params("addr_hrp"))
    # Or with custom parameters
    addr = AtomAddr.EncodeKey(pub_key,
                              hrp="custom")
    # Or with the default parameters from BIP:
    addr = AtomAddr.EncodeKey(pub_key,
                              **Bip44Conf.Cosmos.AddrParams())
    addr = AtomAddr.EncodeKey(pub_key,
                              **Bip44Conf.Kava.AddrParams())
    # Filecoin address
    addr = FilSecp256k1Addr.EncodeKey(pub_key)
    # OKEx Chain address
    addr = OkexAddr.EncodeKey(pub_key)
    # Harmony One address
    addr = OneAddr.EncodeKey(pub_key)
    # Ripple address
    addr = XrpAddr.EncodeKey(pub_key)
    # Zilliqa address
    addr = ZilAddr.EncodeKey(pub_key)

    #
    # Addresses that require a ed25519 curve
    #

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519PublicKey.FromBytes(binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))

    # Algorand address
    addr = AlgoAddr.EncodeKey(pub_key)
    # Elrond address
    addr = EgldAddr.EncodeKey(pub_key)

    # Solana address
    addr = SolAddr.EncodeKey(pub_key)

    # Stellar address
    addr = XlmAddr.EncodeKey(pub_key,
                             addr_type=XlmAddrTypes.PUB_KEY)
    addr = XlmAddr.EncodeKey(pub_key,
                             **Bip44Conf.Stellar.AddrParams())

    # Substrate address with parameters from generic configuration
    addr = SubstrateEd25519Addr.EncodeKey(pub_key,
                                          ss58_format=CoinsConf.Polkadot.Params("addr_ss58_format"))
    # Or with custom parameters
    addr = SubstrateEd25519Addr.EncodeKey(pub_key,
                                          ss58_format=5)
    # Or with the default parameters from BIP/Substrate:
    addr = SubstrateEd25519Addr.EncodeKey(pub_key,
                                          **Bip44Conf.PolkadotEd25519Slip.AddrParams())
    addr = SubstrateEd25519Addr.EncodeKey(pub_key,
                                          **SubstrateConf.Polkadot.AddrParams())

    # Tezos address with custom parameters
    addr = XtzAddr.EncodeKey(pub_key,
                             prefix=XtzAddrPrefixes.TZ1)
    # Or with the default parameters from BIP:
    addr = XtzAddr.EncodeKey(pub_key,
                             **Bip44Conf.Tezos.AddrParams())

    #
    # Addresses that require a ed25519-blake2b curve
    #

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519Blake2bPublicKey.FromBytes(binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))

    # Nano address
    addr = NanoAddr.EncodeKey(pub_key)

    #
    # Addresses that require a ed25519-monero curve
    #

    # Public key bytes or a public key object can be used
    pub_skey = binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422")
    pub_skey = Ed25519MoneroPublicKey.FromBytes(binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422"))
    pub_vkey = binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5")
    pub_vkey = Ed25519MoneroPublicKey.FromBytes(binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5"))

    # Monero address
    addr = XmrAddr.EncodeKey(pub_skey,
                             pub_vkey=pub_vkey,
                             net_ver=CoinsConf.MoneroMainNet.Params("addr_net_ver"))
    # Equivalent
    addr = XmrAddr.EncodeKey(pub_skey,
                             pub_vkey=pub_vkey,
                             net_ver=MoneroConf.MainNet.AddrNetVersion())

    # Monero integrated address
    addr = XmrIntegratedAddr.EncodeKey(pub_skey,
                                       pub_vkey=pub_vkey,
                                       net_ver=CoinsConf.MoneroMainNet.Params("addr_int_net_ver"),
                                       payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    # Equivalent
    addr = XmrIntegratedAddr.EncodeKey(pub_skey,
                                       pub_vkey=pub_vkey,
                                       net_ver=MoneroConf.MainNet.IntegratedAddrNetVersion(),
                                       payment_id=binascii.unhexlify(b"d7af025ab223b74e"))

    #
    # Addresses that require a nist256p1 curve
    #

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b")
    pub_key = Nist256p1PublicKey.FromBytes(binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b"))

    # NEO address with parameters from generic configuration
    addr = NeoAddr.EncodeKey(pub_key,
                             ver=CoinsConf.Neo.Params("addr_ver"))
    # Or with custom parameters
    addr = NeoAddr.EncodeKey(pub_key,
                             ver=b"\x10")
    # Or with the default parameters from BIP:
    addr = NeoAddr.EncodeKey(pub_key,
                             **Bip44Conf.Neo.AddrParams())

    #
    # Addresses that require a sr25519 curve
    #

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Sr25519PublicKey.FromBytes(binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))

    # Substrate address (like before)
    addr = SubstrateSr25519Addr.EncodeKey(pub_key,
                                          ss58_format=CoinsConf.Kusama.Params("addr_ss58_format"))
    addr = SubstrateSr25519Addr.EncodeKey(pub_key,
                                          ss58_format=3)
    addr = SubstrateSr25519Addr.EncodeKey(pub_key,
                                          **SubstrateConf.Kusama.AddrParams())

## WIF

This library is used internally by the other modules, but it's available also for external use.

**Code example**

    import binascii
    from bip_utils import Bip44Conf, CoinsConf, Secp256k1PrivateKey, WifDecoder, WifEncoder

    # Private key bytes or a private key object can be used
    priv_key = binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67')
    priv_key = Secp256k1PrivateKey.FromBytes(binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67'))

    # Encode/Decode with default parameters (Bitcoin main net)
    enc = WifEncoder.Encode(priv_key)
    dec = WifDecoder.Decode(enc)
    # Encode/Decode with parameters from configuration
    # (MN = main net, TN = test net)
    enc = WifEncoder.Encode(priv_key,
                            CoinsConf.BitcoinMainNet.Params("wif_net_ver"))
    dec = WifDecoder.Decode(enc,
                            CoinsConf.BitcoinMainNet.Params("wif_net_ver"))
    # Encode/Decode with parameters from BIP
    enc = WifEncoder.Encode(priv_key,
                            Bip44Conf.BitcoinMainNet.WifNetVersion())
    dec = WifDecoder.Decode(enc,
                            Bip44Conf.BitcoinMainNet.WifNetVersion())
    # Encode/Decode with custom parameters
    enc = WifEncoder.Encode(priv_key,
                            b"\x00")
    dec = WifDecoder.Decode(enc,
                            b"\x00")

## Base58

This library is used internally by the other modules, but it's available also for external use.\
It supports both normal encode/decode and check_encode/check_decode with Bitcoin and Ripple alphabets (if not specified, the Bitcoin one will be used by default):

|Alphabet|Enum|
|---|---|
|Bitcoin|*Base58Alphabets.BITCOIN*|
|Ripple|*Base58Alphabets.RIPPLE*|

**Code example**

    import binascii
    from bip_utils import Base58Alphabets, Base58Decoder, Base58Encoder, Base58XmrDecoder, Base58XmrEncoder

    data_bytes = binascii.unhexlify(b"636363")

    # Normal encode
    enc = Base58Encoder.Encode(data_bytes)
    # Check encode
    chk_enc = Base58Encoder.CheckEncode(data_bytes)

    # Normal decode
    dec = Base58Decoder.Decode(enc)
    # Check decode, Base58ChecksumError is raised if checksum verification fails
    chk_dec = Base58Decoder.CheckDecode(chk_enc)

    # Same as before with Ripple alphabet
    enc = Base58Encoder.Encode(data_bytes, Base58Alphabets.RIPPLE)
    chk_enc = Base58Encoder.CheckEncode(data_bytes, Base58Alphabets.RIPPLE)
    dec = Base58Decoder.Decode(enc, Base58Alphabets.RIPPLE)
    chk_dec = Base58Decoder.CheckDecode(chk_enc, Base58Alphabets.RIPPLE)

    # Encode/Decode using Monero variation
    enc = Base58XmrEncoder.Encode(data_bytes)
    dec = Base58XmrDecoder.Decode(enc)

## SS58

This library is used internally by the other modules, but it's available also for external use.\
It allows encoding/deconding in SS58 format (2-byte checksum).

**Code example**

    import binascii
    from bip_utils import SS58Decoder, SS58Encoder

    data_bytes = binascii.unhexlify(b"e92b4b43a62fa66293f315486d66a67076e860e2aad76acb8e54f9bb7c925cd9")

    # Encode
    enc = SS58Encoder.Encode(data_bytes, ss58_format=0)
    # Decode
    ss58_format, dec = SS58Decoder.Decode(enc)

## Bech32

This library is used internally by the other modules, but it's available also for external use.

**Code example**

    import binascii
    from bip_utils import (
        Bech32Decoder, Bech32Encoder, BchBech32Encoder, BchBech32Decoder, SegwitBech32Decoder, SegwitBech32Encoder
    )

    data_bytes = binascii.unhexlify(b'9c90f934ea51fa0f6504177043e0908da6929983')

    # Encode with bech32
    enc = Bech32Encoder.Encode("cosmos", data_bytes)
    # Decode with bech32
    dec = Bech32Decoder.Decode("cosmos", enc)

    # Encode with segwit bech32
    enc = SegwitBech32Encoder.Encode("bc", 0, data_bytes)
    # Decode with segwit bech32
    wit_ver, wit_prog = SegwitBech32Decoder.Decode("bc", enc)

    # Encode with BCH bech32
    enc = BchBech32Encoder.Encode("bitcoincash", b"\x00", data_bytes)
    # Decode with BCH bech32
    net_ver, dec = BchBech32Decoder.Decode("bitcoincash", enc)

## Code examples

Some examples from mnemonic generation to wallet addresses.

**BIP44**

    from bip_utils import (
        Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Changes, Bip44Coins, Bip44
    )

    # Generate random mnemonic
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Construct from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    # Print master key
    print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Master key (extended): {bip44_mst_ctx.PrivateKey().ToExtended()}")
    print(f"Master key (WIF): {bip44_mst_ctx.PrivateKey().ToWif()}")

    # Generate BIP44 account keys: m/44'/0'/0'
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    # Generate BIP44 chain keys: m/44'/0'/0'/0
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

    # Generate the first 10 addresses: m/44'/0'/0'/0/i
    for i in range(10):
        bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
        print(f"{i}. Address public key (extended): {bip44_addr_ctx.PublicKey().ToExtended()}")
        print(f"{i}. Address private key (extended): {bip44_addr_ctx.PrivateKey().ToExtended()}")
        print(f"{i}. Address: {bip44_addr_ctx.PublicKey().ToAddress()}")

**BIP49**

    from bip_utils import (
        Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Changes, Bip49Coins, Bip49
    )

    # Generate random mnemonic
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Construct from seed
    bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.LITECOIN)
    # Print master key
    print(f"Master key (bytes): {bip49_mst_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Master key (extended): {bip49_mst_ctx.PrivateKey().ToExtended()}")
    print(f"Master key (WIF): {bip49_mst_ctx.PrivateKey().ToWif()}")

    # Generate BIP49 account keys: m/49'/0'/0'
    bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)
    # Generate BIP49 chain keys: m/49'/0'/0'/0
    bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

    # Generate the first 10 addresses: m/49'/0'/0'/0/i
    for i in range(10):
        bip49_addr_ctx = bip49_chg_ctx.AddressIndex(i)
        print(f"{i}. Address public key (extended): {bip49_addr_ctx.PublicKey().ToExtended()}")
        print(f"{i}. Address private key (extended): {bip49_addr_ctx.PrivateKey().ToExtended()}")
        print(f"{i}. Address: {bip49_addr_ctx.PublicKey().ToAddress()}")

**Substrate based on BIP44**

    from bip_utils import (
        Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Changes, Bip44Coins, Bip44
    )

    # Generate random mnemonic
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Construct from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.POLKADOT_ED25519_SLIP)
    # Print master key
    print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")

    # Derive default path
    bip_obj_def = bip44_mst_ctx.DeriveDefaultPath()
    # Print default keys and address
    print(f"Default public key (hex): {bip_obj_def.PublicKey().RawCompressed().ToHex()}")
    print(f"Default private key (hex): {bip_obj_def.PrivateKey().Raw().ToHex()}")
    print(f"Default address: {bip_obj_def.PublicKey().ToAddress()}")

**Substrate based on the official Polkadot wallet**

    import binascii
    from bip_utils import (
        Bip39WordsNum, Bip39MnemonicGenerator, SubstrateBip39SeedGenerator, SubstrateCoins, Substrate
    )

    # Generate random mnemonic
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = SubstrateBip39SeedGenerator(mnemonic).Generate()

    # Construct from seed
    substrate_ctx = Substrate.FromSeed(seed_bytes, SubstrateCoins.POLKADOT)
    # Print master keys and address
    print(f"Master private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Master public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
    print(f"Address: {substrate_ctx.PublicKey().ToAddress()}")

    # Derive a child key
    substrate_ctx = substrate_ctx.ChildKey("//hard")
    # Print derived keys and address
    print(f"Derived private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Derived public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
    print(f"Derived address: {substrate_ctx.PublicKey().ToAddress()}")
    # Print path
    print(f"Path: {substrate_ctx.Path().ToStr()}")

    # Derive a path
    substrate_ctx = substrate_ctx.DerivePath("//0/1")
    # Print derived keys and address
    print(f"Derived private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Derived public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
    print(f"Derived address: {substrate_ctx.PublicKey().ToAddress()}")
    # Print path
    print(f"Path: {substrate_ctx.Path().ToStr()}")

**Monero based on BIP44**

    import binascii
    from bip_utils import (
        Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Changes, Bip44Coins, Bip44, Monero
    )

    # Generate random mnemonic
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Construct from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP)
    # Print master key
    print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
    print(f"Master key (extended): {bip44_mst_ctx.PrivateKey().ToExtended()}")

    # Derive default path
    bip44_def_ctx = bip44_mst_ctx.DeriveDefaultPath()

    # Create Monero object from the BIP44 private key
    monero = Monero.FromBip44PrivateKey(bip44_def_ctx.PrivateKey().Raw().ToBytes())

    # Print keys
    print(f"Monero private spend key: {monero.PrivateSpendKey().Raw().ToHex()}")
    print(f"Monero private view key: {monero.PrivateViewKey().Raw().ToHex()}")
    print(f"Monero public spend key: {monero.PublicSpendKey().RawCompressed().ToHex()}")
    print(f"Monero public view key: {monero.PublicViewKey().RawCompressed().ToHex()}")

    # Print primary address
    print(f"Monero primary address: {monero.PrimaryAddress()}")
    # Print integrated address
    payment_id = binascii.unhexlify(b"d6f093554c0daa94")
    print(f"Monero integrated address: {monero.IntegratedAddress(payment_id)}")
    # Print the first 5 subaddresses for account 0 and 1
    for acc_idx in range(2):
        for subaddr_idx in range(5):
            print(f"Subaddress (account: {acc_idx}, {subaddr_idx}): {monero.Subaddress(subaddr_idx, acc_idx)}")

**Monero based on official Monero wallet**

    import binascii
    from bip_utils import (
        MoneroWordsNum, MoneroMnemonicGenerator, MoneroSeedGenerator, Bip44Changes, Bip44Coins, Bip44, Monero
    )

    # Generate random mnemonic
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    print(f"Mnemonic string: {mnemonic}")
    # Generate seed from mnemonic
    seed_bytes = MoneroSeedGenerator(mnemonic).Generate()

    # Construct from seed
    monero = Monero.FromSeed(seed_bytes)

    # Print keys
    print(f"Monero private spend key: {monero.PrivateSpendKey().Raw().ToHex()}")
    print(f"Monero private view key: {monero.PrivateViewKey().Raw().ToHex()}")
    print(f"Monero public spend key: {monero.PublicSpendKey().RawCompressed().ToHex()}")
    print(f"Monero public view key: {monero.PublicViewKey().RawCompressed().ToHex()}")

    # Print primary address
    print(f"Monero primary address: {monero.PrimaryAddress()}")
    # Print integrated address
    payment_id = binascii.unhexlify(b"d6f093554c0daa94")
    print(f"Monero integrated address: {monero.IntegratedAddress(payment_id)}")
    # Print the first 5 subaddresses for account 0 and 1
    for acc_idx in range(2):
        for subaddr_idx in range(5):
            print(f"Subaddress (account: {acc_idx}, {subaddr_idx}): {monero.Subaddress(subaddr_idx, acc_idx)}")

# Buy me a coffee

You know, I'm italian and I love drinking coffee (especially while coding :D). So, if you'd like to buy me one:
- BTC: bc1qq4r9cglwzd6f2hzxvdkucmdejvr9h8me5hy0k8
- ERC20/BEP20: 0xf84e4898E5E10bf1fBe9ffA3EEC845e82e364b5B

Thank you very much for your support.

# License

This software is available under the MIT license.
