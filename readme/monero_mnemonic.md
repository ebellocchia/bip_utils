## Monero mnemonic library

If you use the official Monero wallet, you'll probably notice that Monero generates mnemonic in its own way, which is different from BIP-0039.\
In fact, it uses different words lists (with 1626 words instead of 2048) and a different algorithm for encoding/decoding the mnemonic string.

The functionalities of this library are the same of the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one but with Monero-style mnemonics:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

### Library usage

The usage of the Monero mnemonic library is basically equivalent to the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one,
just replace the `Bip39` prefix with `Monero`.\
The only differences are:
- It's possible to generate mnemonics both with and without checksum
- It's not possible to use a passphrase for seed generation like BIP-0039

The generated seed can be then used to construct a `Monero` class using the `Monero.FromSeed` method, see the [related paragraph](https://github.com/ebellocchia/bip_utils/tree/master/readme/monero.md).

Supported words number:

|Words number|Enum|Description|
|---|---|---|
|12|`MoneroWordsNum.WORDS_NUM_12`|No checksum|
|13|`MoneroWordsNum.WORDS_NUM_13`|Like before with checksum|
|24|`MoneroWordsNum.WORDS_NUM_24`|No checksum|
|25|`MoneroWordsNum.WORDS_NUM_25`|Like before with checksum|

Now, Monero wallets use 25 words (24 is exactly the same but without the last checksum word).\
The 12/13 words mnemonic was an old format used by MyMonero. It's supported only for compatibility but it's not suggested to use mnemonics with those lengths.

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|128|`MoneroEntropyBitLen.BIT_LEN_128`|
|256|`MoneroEntropyBitLen.BIT_LEN_256`|

Supported languages:

|Language|Enum|
|---|---|
|Chinese (simplified)|`MoneroLanguages.CHINESE_SIMPLIFIED`|
|Dutch|`MoneroLanguages.DUTCH`|
|English|`MoneroLanguages.ENGLISH`|
|French|`MoneroLanguages.FRENCH`|
|German|`MoneroLanguages.GERMAN`|
|Italian|`MoneroLanguages.ITALIAN`|
|Japanese|`MoneroLanguages.JAPANESE`|
|Portuguese|`MoneroLanguages.PORTUGUESE`|
|Spanish|`MoneroLanguages.SPANISH`|
|Russian|`MoneroLanguages.RUSSIAN`|

**Code example (mnemonic generation)**

    import binascii
    from bip_utils import (
        MoneroEntropyBitLen, MoneroEntropyGenerator, MoneroLanguages, MoneroWordsNum,
        MoneroMnemonicEncoder, MoneroMnemonicGenerator
    )
    
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
    
    # Alternatively, the mnemonic can be generated from entropy using the encoder
    mnemonic = MoneroMnemonicEncoder(MoneroLanguages.ENGLISH).EncodeNoChecksum(entropy_bytes)
    mnemonic = MoneroMnemonicEncoder(MoneroLanguages.ENGLISH).EncodeWithChecksum(entropy_bytes)
    mnemonic = MoneroMnemonicEncoder().EncodeNoChecksum(entropy_bytes)
    mnemonic = MoneroMnemonicEncoder().EncodeWithChecksum(entropy_bytes)

**Code example (mnemonic validation)**

    from bip_utils import (
        MnemonicChecksumError, MoneroLanguages, MoneroWordsNum, MoneroMnemonic,
        MoneroMnemonicGenerator, MoneroMnemonicValidator, MoneroMnemonicDecoder
    )
    
    # Mnemonic can be generated with MoneroMnemonicGenerator
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "vials licks gulp people reorder tulips acquire cool lunar upwards recipe against ambush february shelter textbook annoyed veered getting swagger paradise total dawn duets getting"
    # Or from a list
    mnemonic = MoneroMnemonic.FromList(mnemonic.split())
    
    # Get if a mnemonic is valid with automatic language detection, return bool
    is_valid = MoneroMnemonicValidator().IsValid(mnemonic)
    # Same but specifying the language
    is_valid = MoneroMnemonicValidator(MoneroLanguages.ENGLISH).IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        MoneroMnemonicValidator().Validate(mnemonic)
        # Valid...
    except MnemonicChecksumError:
        # Invalid checksum...
        pass
    except ValueError:
        # Invalid length or language...
        pass
    
    # Use MoneroMnemonicDecoder to get back the entropy bytes from a mnemonic, specifying the language
    entropy_bytes = MoneroMnemonicDecoder(MoneroLanguages.ENGLISH).Decode(mnemonic)
    # Like before with automatic language detection
    entropy_bytes = MoneroMnemonicDecoder().Decode(mnemonic)

**Code example (mnemonic seed generation)**

    from bip_utils import MoneroLanguages, MoneroWordsNum, MoneroMnemonicGenerator, MoneroSeedGenerator
    
    # Mnemonic can be generated with MoneroMnemonicGenerator
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "ockhuizen essing brevet symboliek kart slordig hoeve olifant rodijk altsax creatie kneedbaar vetstaart exotherm laxeerpil lekdicht luikenaar bemiddeld oudachtig josua elburg kieviet escort dimbaar kieviet"
    
    # Generate with automatic language detection
    # Like before, the mnemonic can be a string or a Mnemonic object
    seed_bytes = MoneroSeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = MoneroSeedGenerator(mnemonic, MoneroLanguages.DUTCH).Generate()
