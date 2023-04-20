# BIP Utility Library
[![PyPI version](https://badge.fury.io/py/bip-utils.svg)](https://badge.fury.io/py/bip-utils)
[![Build Status](https://travis-ci.com/ebellocchia/bip_utils.svg?branch=master)](https://travis-ci.com/ebellocchia/bip_utils)
[![Documentation Status](https://readthedocs.org/projects/bip-utils/badge/?version=latest)](https://bip-utils.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/ebellocchia/bip_utils/branch/master/graph/badge.svg)](https://codecov.io/gh/ebellocchia/bip_utils)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/9a0c9c6a3d6444fab91f58fe8ec9e35c)](https://www.codacy.com/gh/ebellocchia/bip_utils/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ebellocchia/bip_utils&amp;utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/ebellocchia/bip_utils/badge)](https://www.codefactor.io/repository/github/ebellocchia/bip_utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/ebellocchia/bip_utils/master/LICENSE)

## Introduction

This package allows generating mnemonics, seeds, private/public keys and addresses for different types of cryptocurrencies. In particular:
- Mnemonic and seed generation as defined by [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- Private key encryption/decryption as defined by [BIP-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
- Keys derivation as defined by:
  - [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  - [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
  - [BIP32-Ed25519 (Khovratovich/Law)](https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf)
- Derivation of a hierarchy of keys as defined by:
  - [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
  - [BIP-0049](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) (Bitcoin Segwit)
  - [BIP-0084](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) (Bitcoin Native Segwit)
  - [BIP-0086](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) (Bitcoin Taproot)
  - [CIP-1852](https://cips.cardano.org/cips/cip1852)
- Mnemonic and seed generation for [Substrate](https://wiki.polkadot.network/docs/learn-accounts#seed-generation) (Polkadot/Kusama ecosystem)
- Keys derivation for [Substrate](https://wiki.polkadot.network/docs/learn-accounts#derivation-paths) (Polkadot/Kusama ecosystem, same of Polkadot-JS)
- Keys and addresses generation for Cardano (Byron-Legacy, Byron-Icarus and Shelley, same of Ledger and AdaLite/Yoroi wallets)
- Mnemonic and seed generation for Monero
- Keys and addresses/subaddresses generation for Monero (same of official Monero wallet)
- Mnemonic and seed generation for Algorand (Algorand 25-word mnemonic)
- Mnemonic and seed generation like Electrum wallet (v1 and v2)
- Keys derivation like Electrum wallet (v1 and v2)

Other implemented functionalities:
- Parse BIP-0032 derivation paths
- Parse Substrate derivation paths
- Extended key serialization as defined by [SLIP-0032](https://github.com/satoshilabs/slips/blob/master/slip-0032.md)
- Encode/Decode addresses for all the supported coins
- Encode/Decode [WIF](https://en.bitcoin.it/wiki/Wallet_import_format)
- Encode/Decode [base58](https://en.bitcoin.it/wiki/Base58Check_encoding#Background) and [base58 monero](https://monerodocs.org/cryptography/base58)
- Encode/Decode [ss58](https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58))
- Encode/Decode [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
- Encode/Decode [Bitcoin Cash bech32](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
- Get token account addresses for SPL tokens (i.e. Solana tokens)

Package dependencies:
- [cbor2](https://pypi.org/project/cbor2/) for CBOR encoding/decoding
- [crcmod](https://pypi.org/project/crcmod/) for CRC computation
- [pycryptodome](https://pypi.org/project/pycryptodome/) for cryptographic functions
- [coincurve](https://pypi.org/project/coincurve/) for secp256k1 curve
- [ecdsa](https://pypi.org/project/ecdsa/) for nist256p1 and secp256k1 curves
- [ed25519-blake2b](https://pypi.org/project/ed25519-blake2b/) for ed25519-blake2b curve
- [pynacl](https://pypi.org/project/PyNaCl/) for ed25519 curve
- [py-sr25519-bindings](https://pypi.org/project/py-sr25519-bindings/) for sr25519 curve

Please note that, for the py-sr25519-bindings library, Rust is required to be installed.

## Supported coins

Supported BIP coins:
- Akash Network
- Algorand
- Aptos
- Avalanche (all the 3 chains)
- Axelar
- Band Protocol
- Binance Chain
- Binance Smart Chain
- Bitcoin (and related test net)
- Bitcoin Cash (and related test net)
- Bitcoin Cash Simple Ledger Protocol (and related test net)
- BitcoinSV (and related test net)
- Cardano (Byron-Legacy, Byron-Icarus and Shelley)
- Celo
- Certik
- Cosmos
- Dash (and related test net)
- Dogecoin (and related test net)
- eCash (and related test net)
- Elrond
- EOS
- Ergo (and related test net)
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
- Monero (based on BIP44 and secp256k1 or ed25519 SLIP-0010, it won't generate the same addresses of the official wallets, but it supports subaddresses generation)
- Nano
- Near Protocol
- NEO
- OKEx Chain (Ethereum and Cosmos addresses)
- Ontology
- Osmosis
- Pi Network
- Polkadot (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
- Polygon
- Ripple
- Secret Network
- Solana
- Stellar
- Terra
- Tezos
- Theta Network
- Tron
- VeChain
- Verge
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

Clearly, for those coins that support Smart Contracts (e.g. Ethereum, Tron, ...), the generated keys and addresses are valid for all the related tokens.

## Install the package

For the secp256k1 curve, it's possible to use either the *coincurve* or the *ecdsa* library. *coincurve* is much faster since it's a Python wrapper to the secp256k1 C library, while *ecdsa* is a pure Python implementation.\
By default *coincurve* will be used, but it's possible to disable it when installing.

To install the package:
- Default installation (*coincurve* will be used for secp256k1)
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

**NOTES:**
- if you are using an Apple M1, please make sure to update *coincurve* to version 17.0.0
- in case of problems when building the *ed25519_blake2b* library, you can try one of the prebuilt wheels [here](https://github.com/ebellocchia/bip_utils/tree/master/libs_wheels)

To run tests:

    python -m unittest discover

Or you can install *tox*:

    pip install tox

And then simply run it:

    tox

This will run code coverage with different Python versions and perform style and code analysis.\
For quick test:

    tox -e unittest

## Modules description

- [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md)
- [Algorand mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/algorand_mnemonic.md)
- [Electrum mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/electrum_mnemonic.md)
- [Monero mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/monero_mnemonic.md)
- [BIP-0038](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip38.md)
- [BIP-0032](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip32.md)
- [BIP-0044](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip44.md)
- [Cardano](https://github.com/ebellocchia/bip_utils/tree/master/readme/cardano.md)
- [Electrum](https://github.com/ebellocchia/bip_utils/tree/master/readme/electrum.md)
- [Monero](https://github.com/ebellocchia/bip_utils/tree/master/readme/monero.md)
- [Substrate](https://github.com/ebellocchia/bip_utils/tree/master/readme/substrate.md)
- [Utility libraries](https://github.com/ebellocchia/bip_utils/tree/master/readme/utility_libs.md)

## Documentation

The library documentation is available at [bip-utils.readthedocs.io](https://bip-utils.readthedocs.io).

## Code examples

For some complete code examples (from mnemonic to keys generation), refer to the [examples](https://github.com/ebellocchia/bip_utils/tree/master/examples) folder.

# Buy me a coffee

You know, I'm italian and I love drinking coffee (especially while coding 😃). So, if you'd like to buy me one:
- BTC: `bc1qq4r9cglwzd6f2hzxvdkucmdejvr9h8me5hy0k8`
- ERC20/BEP20: `0xf84e4898E5E10bf1fBe9ffA3EEC845e82e364b5B`

Thank you very much for your support.

# License

This software is available under the MIT license.
