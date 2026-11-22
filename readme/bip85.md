## BIP-0085 library

The BIP-0085 library allows deriving deterministic entropy from a BIP-0032 master key, as defined by [BIP-0085](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki).\
The entropy is used to generate mnemonics, keys and passwords for other wallets, so that a single master key is enough for backing up all of them.

Supported applications:

|Application|Number|Method|
|---|---|---|
|BIP39|39'|`Bip85.Bip39`|
|HD-Seed WIF|2'|`Bip85.HdSeedWif`|
|XPRV|32'|`Bip85.Xprv`|
|HEX|128169'|`Bip85.Hex`|
|PWD BASE64|707764'|`Bip85.PwdBase64`|
|PWD BASE85|707785'|`Bip85.PwdBase85`|
|DICE|89101'|`Bip85.Dice`|
|Nostr|128002'|`Bip85.Nostr`|

The RSA and RSA GPG applications (828365') are not implemented, since the resulting keys depend on the RSA key generation algorithm.
However, the `Bip85Drng` class implements the BIP85-DRNG-SHAKE256 generator required by them.

**NOTES**

- A `Bip85` object can only be constructed from a secp256k1 private master key (i.e. depth 0), as assumed by the specification.
- `DeriveEntropy` only accepts fully hardened paths. The applications always use hardened indexes, so their parameters shall be lower than 2^31.
- The BIP39 application supports all the languages of the BIP-0039 library (i.e. all the languages of the specification, except Japanese).
- The XPRV application serializes the key with the same key net versions of the master key, so a test net master key results in a *tprv*.
- The identity and account index 0 of the Nostr application are reserved by the specification, so they start from 1.

**Code example**

    from bip_utils import Bip32Slip10Secp256k1, Bip39Languages, Bip39SeedGenerator, Bip39WordsNum, Bip85, Bip85Drng

    # Construct from seed
    seed_bytes = Bip39SeedGenerator("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").Generate()
    bip85 = Bip85.FromSeed(seed_bytes)
    # Or from a BIP32 object
    bip85 = Bip85(Bip32Slip10Secp256k1.FromSeed(seed_bytes))
    # Or from an extended master key (in this case, the one of the BIP-0085 test vectors)
    bip85 = Bip85.FromExtendedKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")

    # BIP39 mnemonic (language, words number, index)
    # girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose
    print(bip85.Bip39(Bip39Languages.ENGLISH, Bip39WordsNum.WORDS_NUM_12, 0).ToStr())
    # WIF private key (index)
    # Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp
    print(bip85.HdSeedWif(0))
    # Extended private master key (index)
    # xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX
    print(bip85.Xprv(0))
    # Entropy in hex format (bytes number, index)
    print(bip85.Hex(64, 0))
    # Passwords (length, index)
    # dKLoepugzdVJvdL56ogNV
    print(bip85.PwdBase64(21, 0))
    # _s`{TW89)i4`
    print(bip85.PwdBase85(12, 0))
    # Dice rolls (sides, rolls, index)
    # [1, 0, 0, 2, 0, 1, 5, 5, 2, 4]
    print(bip85.Dice(6, 10, 0))
    # Nostr private key in nsec format (identity, account index)
    # nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz
    print(bip85.Nostr(1, 1))

    # Raw entropy (64-byte) from a custom path, which shall be fully hardened
    entropy_bytes = bip85.DeriveEntropy("m/83696968'/0'/0'")
    # DRNG seeded with the entropy, the output can be read incrementally
    drng = Bip85Drng(entropy_bytes)
    print(drng.Read(32).hex())
    print(drng.Read(48).hex())
