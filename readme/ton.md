## TON library

The TON library allows to generate and validate mnemonics, generate seeds and keys with the same algorithm of `ton-crypto`.

### TON Mnemonics

The usage of TON mnemonics is much simpler than other mnemonic modules, since there is no decoder/encoder but only generation and validation.

Supported words number:

|Words number|Enum|
|---|---|
|25|`TonWordsNum.WORDS_NUM_24`|

Supported languages:

|Language|Enum|
|---|---|
|English|`TonLanguages.ENGLISH`|

**Code example (mnemonic generation)**

    from bip_utils import TonLanguages, TonWordsNum, TonMnemonicGenerator

    # Generate a random mnemonic string of 24 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)

    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())

    # Generate a random mnemonic string of 24 words by specifying the language
    mnemonic = TonMnemonicGenerator(TonLanguages.ENGLISH).FromWordsNumber(TonWordsNum.WORDS_NUM_24)

**Code example (mnemonic validation)**

    from bip_utils import (
        TonLanguages, TonWordsNum, TonMnemonic, TonMnemonicGenerator, TonMnemonicValidator,
    )

    # Mnemonic can be generated with TonMnemonicGenerator
    mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
    # Or it can be a string
    mnemonic = "dove option fame breeze orchard ecology pizza flight miracle film lemon dwarf axis tone soldier nut flavor wheat dish express path private sea ladder"
    # Or from a list
    mnemonic = TonMnemonic.FromList(mnemonic.split())

    # Get if a mnemonic is valid with automatic language detection, return bool
    is_valid = TonMnemonicValidator().IsValid(mnemonic)
    # Same but specifying the language
    is_valid = TonMnemonicValidator(TonLanguages.ENGLISH).IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        TonMnemonicValidator().Validate(mnemonic)
        # Valid...
    except ValueError:
        # Invalid length or language...
        pass

**Code example (mnemonic seed generation)**

    from bip_utils import TonLanguages, TonWordsNum, TonMnemonicGenerator, TonSeedGenerator, TonSeedTypes

    # Mnemonic can be generated with TonMnemonicGenerator
    mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
    # Or it can be a string
    mnemonic = "dove option fame breeze orchard ecology pizza flight miracle film lemon dwarf axis tone soldier nut flavor wheat dish express path private sea ladder"

    # Generate seed for private key (automatic language detection)
    seed_bytes = TonSeedGenerator(mnemonic).Generate()
    seed_bytes = TonSeedGenerator(mnemonic).Generate(TonSeedTypes.PRIVATE_KEY)
    # Generate seed for HD keys (automatic language detection)
    seed_bytes = TonSeedGenerator(mnemonic).Generate(TonSeedTypes.HD_KEY)
    # Generate specifying the language
    seed_bytes = TonSeedGenerator(mnemonic, lang=TonLanguages.ENGLISH).Generate()

### TON Keys Derivation

For deriving keys and getting addresses, a `Ton` class shall be created.

**Code example**

    from bip_utils import Ton, TonAddrVersions, TonMnemonicGenerator, TonSeedGenerator, TonWordsNum

    # Generate mnemonic and seed for private key
    mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
    seed_bytes = TonSeedGenerator(mnemonic).Generate()

    # Create TON class
    ton = Ton.FromSeed(seed_bytes)
    # Get keys
    print(ton.PublicKey().RawCompressed().ToHex())
    print(ton.PrivateKey().Raw().ToHex())
    # Get address (default: V5R1)
    print(ton.GetAddress())
    # Get address specifying version
    print(ton.GetAddress(version=TonAddrVersions.V3R1))
    print(ton.GetAddress(version=TonAddrVersions.V3R2))
    print(ton.GetAddress(version=TonAddrVersions.V4))
    print(ton.GetAddress(version=TonAddrVersions.V5R1))
