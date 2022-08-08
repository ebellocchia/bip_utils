## Electrum library

The Electrum library is a simple module that allows to generate keys and addresses like Electrum wallet, since it uses
its own derivation paths and algorithms.

### Electrum v1

The `ElectrumV1` class generates keys and addresses using the old Electrum algorithm.\
It shall be used with seeds generated with the `ElectrumV1SeedGenerator` class.\
Since Electrum v1 doesn't follow the BIP-0032 derivation scheme, the returned public/private keys are 
`Secp256k1PublicKey`/`Secp256k1PrivateKey` objects.

An `ElectrumV1` object can be constructed from:
- A seed
- A private key
- A public key

**Code example**

    import binascii
    from bip_utils import (
        CoinsConf,
        ElectrumV1WordsNum, ElectrumV1MnemonicGenerator, ElectrumV1SeedGenerator, ElectrumV1,
        IPrivateKey, WifPubKeyModes, WifEncoder
    )


    # Encode private key to WIF
    def priv_to_wif(priv_key: IPrivateKey,
                    pub_key_mode: WifPubKeyModes = WifPubKeyModes.COMPRESSED) -> str:
        return WifEncoder.Encode(priv_key,
                                 CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"),
                                 pub_key_mode)


    # Generate random mnemonic and seed
    mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
    seed_bytes = ElectrumV1SeedGenerator(mnemonic).Generate()
    # Construct class from seed
    electrum_v1 = ElectrumV1.FromSeed(seed_bytes)
    # Get if public-only
    print(electrum_v1.IsPublicOnly())
    # Print master keys
    print(electrum_v1.MasterPublicKey().RawUncompressed().ToHex()[2:])
    print(priv_to_wif(electrum_v1.MasterPrivateKey(), WifPubKeyModes.UNCOMPRESSED))
    # Derive some addresses
    for i in range(5):
        print(priv_to_wif(electrum_v1.GetPrivateKey(0, i), WifPubKeyModes.UNCOMPRESSED))
        print(electrum_v1.GetAddress(0, i))

    # Construct class from private key
    electrum_v1 = ElectrumV1.FromPrivateKey(
        binascii.unhexlify(b"e1d36931d581b4dcae0bb03929adcfb5ab0cdc0f4886ff6c5098591636ace214")
    )
    # Construct class from public key
    electrum_v1 = ElectrumV1.FromPublicKey(
        binascii.unhexlify(b"02c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4")
    )

### Electrum v2

The `ElectrumV2` classes generate keys and addresses using the current Electrum algorithm.\
It shall be used with seeds generated with the `ElectrumV2SeedGenerator` class.\
Since Electrum v2 follows the BIP-0032 derivation scheme, the classes can also be directly constructed from a `Bip32Slip10Secp256k1` object.
Constructing it from a BIP32 object allows construction from public/private key bytes or extended keys.\
The returned public/private keys are `Bip32PublicKey`/`Bip32PrivateKey` objects.

Two classes are available:
- `ElectrumV2Standard`: generate Bitcoin legacy addresses, like importing a standard seed in Electrum
- `ElectrumV2Segwit`: generate Bitcoin native Segwit addresses, like importing a Segwit seed in Electrum

The usage of these two classes are exactly the same, since they inherit from the same base class.

**Code example**

    from bip_utils import (
        Bip32Slip10Secp256k1,
        CoinsConf,
        ElectrumV2WordsNum, ElectrumV2MnemonicTypes, ElectrumV2MnemonicGenerator, ElectrumV2SeedGenerator,
        ElectrumV2Standard,
        IPrivateKey, WifPubKeyModes, WifEncoder
    )


    # Encode private key to WIF
    def priv_to_wif(priv_key: IPrivateKey,
                    pub_key_mode: WifPubKeyModes = WifPubKeyModes.COMPRESSED) -> str:
        return WifEncoder.Encode(priv_key,
                                 CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"),
                                 pub_key_mode)


    # Generate random mnemonic and seed
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(
        ElectrumV2WordsNum.WORDS_NUM_12)
    seed_bytes = ElectrumV2SeedGenerator(mnemonic).Generate()
    # Construct from seed
    electrum_v2 = ElectrumV2Standard.FromSeed(seed_bytes)
    # Or directly from a Bip32Slip10Secp256k1 object
    electrum_v2 = ElectrumV2Standard(
        Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    )
    # Get if public-only
    print(electrum_v2.IsPublicOnly())
    # Print master keys
    print(electrum_v2.MasterPublicKey().RawUncompressed().ToHex())
    print(priv_to_wif(electrum_v2.MasterPrivateKey().KeyObject()))
    # Derive addresses
    for i in range(5):
        print(priv_to_wif(electrum_v2.GetPrivateKey(0, i).KeyObject()))
        print(electrum_v2.GetAddress(0, i))
