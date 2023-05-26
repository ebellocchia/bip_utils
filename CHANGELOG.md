# 2.7.1

- Fix bug in Bitcoin Taproot address encoding, when the tweaked public key had leading zeros

# 2.7.0

- Add support for Icon
- Use *pynacl* library for Monero ed25519 arithmetics, speeding it up a lot (around 5 times faster on my machine)

# 2.6.1

- Fix CIP1852 Cardano Icarus/Ledger extended key prefix
- Fix `Bip32ChainCode.Length` and `Bip32FingerPrint.Length` methods that were conflicting with the base class method 
- Reformat files with `isort`

# 2.6.0

- Add support for Cardano:
  - Cardano Byron legacy (old Daedalus addresses, i.e. `Ddz...`)
  - Cardano Byron-Icarus (Yoroi addresses in the `Ae2...` format)
  - Cardano Shelley (Yoroi addresses in the `addr1...` format)
- Add support for Ergo (`Bip44Coins.ERGO`, `Bip44Coins.ERGO_TESTNET`)
- Add `ChainCode` method to Bip32 and Bip44 key classes to quickly get it
- Add `PublicKey` method to `Bip44PrivateKey`
- `Bip32Base` class:
  - Add `Curve` method
  - Remove `IsPrivateUnhardenedDerivationSupported` method (same meaning of `IsPublicDerivationSupported`)
- `Bip32KeyIndex` class:
  - `Bip32Utils` methods move to `Bip32KeyIndex`
  - Add `Harden`/`Unharden` methods to `Bip32KeyIndex`
- `DataBytes` class:
  - Add possibility to get length (`Length`, `Size`, `__len__`)
  - Add possibility to check for equality (`__eq__`)
  - Add possibility to iterate over bytes (`__iter__`)
- Add `Curve` method to `Bip32PublicKey`/`Bip32PrivateKey` classes
- Add possibility to create a `Bip32PublicKey` class from an `IPoint` instance
- Add `CurveType` method to `IPoint` classes
- BIP32 classes were renamed in a consistent way:
  - `Bip32Ed25519Slip` -> `Bip32Slip10Ed25519`
  - `Bip32Ed25519Blake2bSlip` -> `Bip32Slip10Ed25519Blake2b`
  - `Bip32Nist256p1` -> `Bip32Slip10Nist256p1`
  - `Bip32Secp256k1` -> `Bip32Slip10Secp256k1`
  - `Bip32Ed25519Kholaw` -> `Bip32KholawEd25519`

  Old classes kept for compatibility
- Update key net version to get `xprv` prefix for BIP32 Kholaw private extended keys

# 2.5.1

- Fix public derivation for `ElectrumV1` and `ElectrumV2` classes
- Check for master key object when constructing a `ElectrumV2Base` class
- Add some utility methods to `ElectrumV1` class (`FromPrivateKey`, `FromPublicKey`)

# 2.5.0

- Add support for Electrum mnemonics and keys derivation (both v1 and v2)
- Module for BIP32 keys serialization/deserialization available for external use
- Add support for Axelar coin
- Add support for uncompressed public keys to `P2PKHAddrEncoder`
- Add support for [SLIP-0032](https://github.com/satoshilabs/slips/blob/master/slip-0032.md)
- `Bip32Path` can distinguish between absolute and relative paths
- `Bip32PathParser` discards empty elements
- Some rework on the *bech32* and *bip32_key_ser* modules

# 2.4.0

- Add local implementation of Substrate SCALE encoding (remove dependency from [scalecodec](https://pypi.org/project/scalecodec/))
- Add support to [BIP32-Ed25519 (Khovratovich/Law)](https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf) derivation scheme
- `Bip32Base.FromPrivateKey` and `Bip32Base.FromPublicKey` can now recover the full derivation data (if specified)
- `Bip44Base.FromPrivateKey` can now recover the full derivation data (if specified)
- Add `Bip44Base.FromPublicKey` method
- Always use Cryptodome for *RIPEMD160*

# 2.3.0

- Add support for Bitcoin Taproot addresses (P2TR)
- Add support for [BIP-0086](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
- Add support for [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
- Add support for Algorand 25-word mnemonic
- Add support for Solana SPL token
- P2WPKH decoding/encoding methods don't need anymore the witness version as parameter, since it's fixed to zero internally (it can still be passed without errors though, it's just ignored)
- Use Cryptodome if *ripemd160* and *sha512_256* algorithms are not available in *hashlib*
- Add documentation using sphinx
- Some refactoring for mnemonic module
- **Breaking changes**:
  - Mnemonic-specific checksum exceptions (i.e. `Bip39ChecksumError` and `MoneroChecksumError`) were replaced by the common `MnemonicChecksumError`

# 2.2.1

- Exported some missing utility classes

# 2.2.0

- Add support for the following coins: Akash Network, Certik, Near Protocol, Osmosis, Secret Network:

|Coin | Main net enum | Test net enum|
|---|---|---|
|Akash Network | `Bip44Coins.AKASH_NETWORK` | - |
|Certik | `Bip44Coins.CERTIK` | - |
|Near Protocol | `Bip44Coins.NEAR_PROTOCOL` | - |
|Osmosis | `Bip44Coins.OSMOSIS` | - |
|Secret Network (old path)|`Bip44Coins.SECRET_NETWORK_OLD`|- |
|Secret Network (new path)|`Bip44Coins.SECRET_NETWORK_NEW`|- |

- Add possibility to decode and validate addresses. The old address classes are split into decoder/encoder classes to maintain the same design of the other decoding/encoding modules (e.g. `AlgoAddrDecoder`, `AlgoAddrEncoder`). The old address classes are kept for compatibility but they are just aliases for the correspondent encoder class (e.g. `AlgoAddr` -> `AlgoAddrEncoder`) .
- Add support to [BIP-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) (with and without EC multiplication)
- Some minor improvements and refactoring

# 2.1.0

- Add support for Celo, eCash and Bitcoin Cash Simple Ledger Protocol:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin Cash SLP|`Bip44Coins.BITCOIN_CASH_SLP`|`Bip44Coins.BITCOIN_CASH_SLP_TESTNET`|
|Celo|`Bip44Coins.CELO`|-|
|eCash|`Bip44Coins.ECASH`|`Bip44Coins.ECASH_TESTNET`|

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin Cash SLP|`Bip49Coins.BITCOIN_CASH_SLP`|`Bip49Coins.BITCOIN_CASH_SLP_TESTNET`|
|eCash|`Bip49Coins.ECASH`|`Bip49Coins.ECASH_TESTNET`|

- Add class `BchAddrConverter` for converting Bitcoin Cash addresses
- Fix point from/to bytes conversion when using *ecdsa* < 0.17

# 2.0.2

- Add configuration files for flake8 and prospector
- Fix all flake8 warnings
- Fix the vast majority of prospector warnings
- Remove all star imports (`import *`)

# 2.0.1

- Fix *setup.py* so that it doesn't include the *tests* folder in the final distribution

# 2.0.0

- Lots of improvements and new features:
  - Add implementation of SLIP-0010
  - Add support for nist256p1, ed25519, ed25519-blake2b and sr25519 curves
  - Add support for new coins based on the new curves (see below)
  - Add support for Substrate (Polkadot ecosystem) keys derivation and addresses generation
  - Add support for Monero mnemonic generation and validation
  - Add support for Monero keys derivation and addresses/subaddresses generation
  - Usage of *coincurve* library for secp256k1 curve (still possible to use *ecdsa*, anyway)
  - Better usage of private and public keys:
    - Improved and more complete class hierarchy and design
    - Easier construction (from bytes, from point, from object)
    - Possibility to pass as argument the key object in addition to key raw bytes (e.g. to methods of Bip and address classes)
    - Keys validation
    - Possibility to use both compressed/uncompressed public keys without the need of converting
  - General code refactoring and re-design to keep everything neat and tidy
- New supported coins:
  - BIP44 coins:
    - Algorand
    - Elrond
    - Filecoin
    - Kusama (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
    - Monero (based on BIP44 and secp256k1 or ed25519 SLIP-0010, it won't generate the same addresses of the official wallets but it supports subaddresses generation)
    - Nano
    - NEO
    - Ontology
    - Polkadot (based on BIP44 and ed25519 SLIP-0010, like TrustWallet, it won't generate the same addresses of Polkadot-JS)
    - Solana
    - Stellar
    - Tezos
    - Theta Network
    - Zilliqa
  - Substrate coins (based on the official wallet, e.g. Polkadot-JS):
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
  - Monero (based on the official wallet)
- **Breaking changes**:
  - `Bip32` class does not exist anymore. It has been replaced by different classes depending on the underlying elliptic curve: `Bip32Ed25519Slip`, `Bip32Ed25519Blake2bSlip`, `Bip32Nist256p1`, `Bip32Secp256k1`
  - `Bip49` and `Bip84` now have their own coin types: `Bip49Coins` and `Bip84Coins`
  - `Bip39MnemonicValidator.GetEntropy` method has been replaced by `Bip39MnemonicDecoder.Decode` method
  - The mnemonic in `Bip39MnemonicValidator` class is passed as argument to the methods instead of the constructor (e.g. `Bip39MnemonicValidator(mnemonic).IsValid()` -> `Bip39MnemonicValidator().IsValid(mnemonic)`)
  - `P2PKH, P2SH and P2WPKH` address classes now have an "Addr" suffix  (i.e. `P2PKHAddr, P2SHAddr and P2WPKHAddr`, same for BCH versions)
  - In address classes, the `ToAddress` method now is called `EncodeKey` (e.g. `EthAddr.ToAddress` -> `EthAddr.EncodeKey`) and the additional parameters shall be explicitly named
  - `AtomBech32Decoder`/`AtomBech32Encoder` is now simply called `Bech32Decoder`/`Bech32Encoder`
  - `P2PKHAddr`/`P2SHAddr`/`P2WPKHAddr` classes do not have anymore Bitcoin net versions as default parameter

# 1.11.1

- Add missing *MANIFEST.in* file, that was preventing the package to be installed from *pip*

# 1.11.0

- Add new BIP-0039 languages:

|Language|Enum|
|---|---|
|Chinese (simplified)|`Bip39Languages.CHINESE_SIMPLIFIED`|
|Chinese (traditional)|`Bip39Languages.CHINESE_TRADITIONAL`|
|Korean|`Bip39Languages.KOREAN`|

- Add support for the following coins:

|Coin|Main net enum|
|---|---|
|Polygon|`Bip44Coins.POLYGON`|
|Fantom Opera|`Bip44Coins.FANTOM_OPERA`|
|Harmony One (Metamask address)|`Bip44Coins.HARMONY_ONE_METAMASK`|
|Harmony One (Ethereum address)|`Bip44Coins.HARMONY_ONE_ETH`|
|Harmony One (Cosmos address)|`Bip44Coins.HARMONY_ONE_ATOM`|
|Huobi Chain|`Bip44Coins.HUOBI_CHAIN`|
|OKEx Chain (Ethereum address)|`Bip44Coins.OKEX_CHAIN_ETH`|
|OKEx Chain (Cosmos address)|`Bip44Coins.OKEX_CHAIN_ATOM`|
|OKEx Chain (Old Cosmos address before mainnet upgrade)|`Bip44Coins.OKEX_CHAIN_ATOM_OLD`|

# 1.10.0

- Add support for Terra (`Bip44Coins.TERRA`)
- Add support for different BIP-0039 languages:

|Language|Enum|
|---|---|
|English|`Bip39Languages.ENGLISH`|
|Italian|`Bip39Languages.ITALIAN`|
|French|`Bip39Languages.FRENCH`|
|Spanish|`Bip39Languages.SPANISH`|
|Portuguese|`Bip39Languages.PORTUGUESE`|
|Czech|`Bip39Languages.CZECH`|

- **Breaking changes**:
  - `Bip39MnemonicGenerator` is not a static class anymore but shall be constructed, for example:

        Bip39MnemonicGenerator().FromWordsNumber(words_num)
        Bip39MnemonicGenerator().FromEntropy(entropy_bytes)

  - `Bip39MnemonicValidator.Validate` now raises exceptions instead of returning a bool
  - Add `Bip39MnemonicValidator.IsValid` that validates a mnemonic returning bool (same as the old `Bip39MnemonicValidator.Validate`)

# 1.9.0

- Add support for AVAX (`Bip44Coins.AVAX_X_CHAIN`, `Bip44Coins.AVAX_C_CHAIN`, `Bip44Coins.AVAX_P_CHAIN`)

# 1.8.0

- Add python typing
- Make the code PEP8 compliant
- Some refactoring to break circular dependencies
- Fix documentation errors

# 1.7.0

- Add support for Binance Smart Chain (`Bip44Coins.BINANCE_SMART_CHAIN`)
- Rename `Bip44Coins.BINANCE_COIN` to `Bip44Coins.BINANCE_CHAIN`

# 1.6.0

- Add `FromAddressPrivKey` method for creating a Bip object from a private key related to an address
- Merge pull request for adding Nine Chronicles Gold

# 1.5.0

- Add support for Ethereum Classic and VeChain

# 1.4.0

- Add support for Kava, IRIS network and Binance Coin

# 1.3.1

- Fix setup.py for loading all packages in sub-folders

# 1.3.0

- Add support for Zcash, Cosmos and Band Protocol
- Organize project into different folders

# 1.2.0

- Add support for Tron

# 1.1.0

- Fix WIF for private keys correspondent to compressed public keys
- Add support for Bitcoin Cash and BitcoinSV
- Refactor Bech32 module to support both Segwit and Bitcoin Cash formats

# 1.0.5

- Add support for Ripple alphabet in `Base58` module. The alphabet is now passed as parameter, so it's possible to choose if encoding/decoding with the Bitcoin or Ripple one (default parameter is Bitcoin to maintain retro-compatibility).

# 1.0.4

- Add `Bip39WordsNum` for enumerating accepted words number and `Bip39EntropyBitLen` for accepted entropy bit lengths
  **NOTE**: `Bip39MnemonicGenerator.FromWordsNumber` and `EntropyGenerator.Generate` methods still accept integers as parameter to maintain retro-compatibility
- Improve *bip39* module

# 1.0.3

- Add binary search algorithm for finding a word in BIP39 words list
- Remove some useless exceptions in `Bip32`, since they those checks are already performed by *ecdsa* library

# 1.0.2

- Minor improvements in `Bip32` module

# 1.0.1

- Fix `BipCoinBase.ComputeAddress` method, raising exception in case of invalid address class

# 1.0.0

- Improve and simplify coin configuration so that it's easier to read, modify and maintain
- Add classes for private and public keys that are in charge of getting keys with different format
- Refactor `Bip32` class
- Move exceptions to separated files
- General code re-factor and improvement

# 0.5.2

- Fix minimum depth for public derivation (set to account level)

# 0.5.1

- Fix bug in `PathParser` class
- Refactor `PathParser` class
- Add possibility to use `p` for hardened indexes, e.g. `m/0'/1'` is the same of `m/0p/1p`

# 0.5.0

- Add some simple methods to Bip classes: `Bip44Base.SpecName`, `Bip44Base.CoinNames`, `Bip44Base.IsCoinAllowed`, `Bip44Base.IsPublicOnly`, `Bip44Base.IsTestNet`
- Add `GetConfig` method to coin helper classes, remove `GetWifNetVersion` method
- Export `EntropyGenerator`
- Rename `Bip32.IsIndexHardened` to `Bip32.IsHardenedIndex`
- Remove `Bip32.SetTestNet` method
- Remove useless exceptions
- Add support for Dogecoin BIP-0049
- Fix DASH WIF main net version and Dogecoin test net versions

# 0.4.0

- Add support for DASH coin (both Bip44 and Bip49 are supported).
- Add *key_helper* module for checking if a key is private or public compressed/uncompressed.
- Add error checking to classes that generate addresses (`P2PKH`, `P2SH`, `P2WPKH`, `EthAddr`, `XrpAddr`). They now raise a `ValueError` exception if the provided key is not valid
- *WIF* module checks for key validity when encoding; when decoding, it checks if the resulting key is valid

# 0.3.0

- Redesign architecture to make easier to add new coins
- Add support for the following coins:
  - Litecoin
  - Dogecoin
  - Ethereum
  - Ripple

# 0.2.0

- Add possibility to create a `Bip32`, `Bip44`, `Bip49` and `Bip84` object from an extended key
- Rename `Bip44Base.Chain` to `Bip44Base.Change`
- Rename `Bip44Chains`to `Bip44Changes`
- Added some helper methods to `Bip44Base` (`IsMasterLevel`, `IsPurposeLevel`, `IsCoinLevel`, `IsAccountLevel`, `IsChangeLevel` and `IsAddressIndexLevel`)

# 0.1.1

- Fix *bip39* module (`self` in `@staticmethod`)

# 0.1.0

Included modules:
- BIP-0039
- BIP-0032 with path parser
- BIP-0044, BIP-0049 and BIP-0084
- P2PKH address generation
- P2SH address generation
- P2WPKH address generation
- WIF encoder/decoder
- base58 encoder/decoder
