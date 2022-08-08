## Electrum mnemonic library

Electrum wallet uses mnemonics generated with a different algorithm with respect to BIP-0039.

The functionalities of this library are the same of the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one but with Electrum-style mnemonics:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

Two mnemonic "versions" are supported:
- [V1, i.e. "old seed" in Electrum](https://github.com/ebellocchia/bip_utils/tree/master/readme/electrum_v1_mnemonic.md)
- [V2, i.e. the current seeds used by Electrum](https://github.com/ebellocchia/bip_utils/tree/master/readme/electrum_v2_mnemonic.md)
