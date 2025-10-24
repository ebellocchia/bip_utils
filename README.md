# BIP Utility Library

| |
|---|
| [![PyPI - Version](https://img.shields.io/pypi/v/bip_utils.svg?logo=pypi&label=PyPI&logoColor=gold)](https://pypi.org/project/bip_utils/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/bip_utils.svg?logo=python&label=Python&logoColor=gold)](https://pypi.org/project/bip_utils/) [![GitHub License](https://img.shields.io/github/license/ebellocchia/bip_utils?label=License)](https://github.com/ebellocchia/bip_utils?tab=MIT-1-ov-file) |
| [![Code Coverage](https://github.com/ebellocchia/bip_utils/actions/workflows/code-coverage.yml/badge.svg)](https://github.com/ebellocchia/bip_utils/actions/workflows/code-coverage.yml) [![Code Analysis](https://github.com/ebellocchia/bip_utils/actions/workflows/code-analysis.yml/badge.svg)](https://github.com/ebellocchia/bip_utils/actions/workflows/code-analysis.yml) [![Build & Test](https://github.com/ebellocchia/bip_utils/actions/workflows/test.yml/badge.svg)](https://github.com/ebellocchia/bip_utils/actions/workflows/test.yml) [![Test Requirements](https://github.com/ebellocchia/bip_utils/actions/workflows/test_min_reqs.yml/badge.svg)](https://github.com/ebellocchia/bip_utils/actions/workflows/test_min_reqs.yml) |
| [![Codecov](https://img.shields.io/codecov/c/github/ebellocchia/bip_utils?label=Code%20Coverage)](https://codecov.io/gh/ebellocchia/bip_utils) [![Codacy grade](https://img.shields.io/codacy/grade/9a0c9c6a3d6444fab91f58fe8ec9e35c?label=Codacy%20Grade)](https://app.codacy.com/gh/ebellocchia/bip_utils/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) [![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/ebellocchia/bip_utils?label=CodeFactor%20Grade)](https://www.codefactor.io/repository/github/ebellocchia/bip_utils) |
| |

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
- Generation of keys from a passphrase chosen by the user ("brainwallet")

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
- Arbitrum
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
- Celestia
- Celo
- Certik
- Cosmos
- Dash (and related test net)
- Digibyte
- Dogecoin (and related test net)
- dYdX
- eCash (and related test net)
- Elrond (MultiversX)
- EOS
- Ergo (and related test net)
- Ethereum
- Ethereum Classic
- Fantom Opera
- Filecoin
- Fetch.ai
- Harmony One (Ethereum and Cosmos addresses)
- Huobi Heco Chain
- IRIS Network
- Kava
- Kusama (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
- Litecoin (and related test net)
- Mavryk
- Metis
- Monero (based on BIP44 and secp256k1 or ed25519 SLIP-0010, it won't generate the same addresses of the official wallets, but it supports subaddresses generation)
- Nano
- Near Protocol
- NEO (legacy and N3)
- Neutron
- Nimiq
- OKEx Chain (Ethereum and Cosmos addresses)
- Ontology
- Optimism
- Osmosis
- Pi Network
- Polkadot (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
- Polygon
- Ripple
- Secret Network
- Solana
- Stafi (Cosmos)
- Stellar
- Sui (only ed25519)
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

The package can be simply installed via *pip*:

    pip install bip_utils

**NOTE:** if you have problems building the *ed25519_blake2b* library (especially on Windows), you can try one of the prebuilt wheels [here](https://github.com/ebellocchia/bip_utils/tree/master/libs_wheels).

### Python 3.7 and 3.8 support

The package works fine with Python 3.7 and 3.8, but it requires Python 3.9 or higher because `pyproject.toml` is not compatible with old versions of *setuptools* and will trigger an error during installation.\
Therefore, for Python 3.7 and 3.8, the `pyproject_legacy.toml` file is provided. Just rename it to `pyproject.toml`, overwriting the existent one, and install the package with *pip* from the local folder:

    pip install .

### Alternative secp256k1 library

For *secp256k1* curve, the package uses *coincurve* by default (much faster). However, it also supports *ecdsa*, which is a pure Python implementation (i.e. slower).

To use *ecdsa* for *secp256k1*, edit the file *bip_utils/ecc/conf.py* and set `USE_COINCURVE` to `False`. Then install with *pip*:

    pip install .

## Test and Coverage

Install develop dependencies:

    pip install -r requirements-dev.txt

To run tests:

    python -m unittest discover

To run tests with coverage:

    coverage run -m unittest discover
    coverage report

To run code analysis, just execute the `analyze_code` script.

## Modules description

- [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md)
- [Algorand mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/algorand_mnemonic.md)
- [Electrum mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/electrum_mnemonic.md)
- [Monero mnemonic](https://github.com/ebellocchia/bip_utils/tree/master/readme/monero_mnemonic.md)
- [BIP-0038](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip38.md)
- [BIP-0032](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip32.md)
- [BIP-0044](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip44.md)
- [Brainwallet](https://github.com/ebellocchia/bip_utils/tree/master/readme/brainwallet.md)
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
- BTC: `bc1qqxwmzs7qyatpht84hqmavkag0r3gnalyjxqr9d`
- EVM: `0xbe6Ce1d8fc6e72173f00A63FF493dFdFdb664FbF`

Thank you very much for your support.

# License

This software is available under the MIT license.
