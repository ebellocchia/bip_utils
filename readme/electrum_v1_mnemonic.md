## Electrum V1 mnemonics

Electrum V1 mnemonics are the old type of mnemonics used by Electrum (called "old seed" by the wallet).
Electrum doesn't generate them anymore but they can still be imported.\
Electrum V1 mnemonics uses its words list with 1626 words and its decoding/encoding algorithm is similar to Moner mnemonics.\
The usage of the Electrum V1 mnemonic library is basically equivalent to the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one,
just replace the `Bip39` prefix with `ElectrumV1`.

Supported words number:

|Words number|Enum|
|---|---|
|12|`ElectrumV1WordsNum.WORDS_NUM_12`|

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|128|`ElectrumV1EntropyBitLen.BIT_LEN_128`|

Supported languages:

|Language|Enum|
|---|---|
|English|`ElectrumV1Languages.ENGLISH`|

**Code example (mnemonic generation)**

    import binascii
    from bip_utils import (
        ElectrumV1EntropyBitLen, ElectrumV1EntropyGenerator, ElectrumV1Languages, ElectrumV1WordsNum,
        ElectrumV1MnemonicEncoder, ElectrumV1MnemonicGenerator
    )
    
    # Generate a random mnemonic string of 12 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
    
    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())
    
    # Generate a random mnemonic string of 12 words by specifying the language
    mnemonic = ElectrumV1MnemonicGenerator(ElectrumV1Languages.ENGLISH).FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
    
    # Generate the mnemonic string from entropy bytes
    entropy_bytes = binascii.unhexlify(b"00000000000000000000000000000000")
    mnemonic = ElectrumV1MnemonicGenerator().FromEntropy(entropy_bytes)
    
    # Generate mnemonic from random 128-bit entropy (with and without checksum)
    entropy_bytes = ElectrumV1EntropyGenerator(ElectrumV1EntropyBitLen.BIT_LEN_128).Generate()
    mnemonic = ElectrumV1MnemonicGenerator().FromEntropy(entropy_bytes)
    
    # Alternatively, the mnemonic can be generated from entropy using the encoder
    mnemonic = ElectrumV1MnemonicEncoder(ElectrumV1Languages.ENGLISH).Encode(entropy_bytes)
    mnemonic = ElectrumV1MnemonicEncoder().Encode(entropy_bytes)

**Code example (mnemonic validation)**

    from bip_utils import (
        ElectrumV1Languages, ElectrumV1WordsNum, ElectrumV1Mnemonic,
        ElectrumV1MnemonicGenerator, ElectrumV1MnemonicValidator, ElectrumV1MnemonicDecoder,
    )
    
    # Mnemonic can be generated with ElectrumV1MnemonicGenerator
    mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
    # Or it can be a string
    mnemonic = "like like like like like like like like like like like like"
    # Or from a list
    mnemonic = ElectrumV1Mnemonic.FromList(mnemonic.split())
    
    # Get if a mnemonic is valid with automatic language detection, return bool
    is_valid = ElectrumV1MnemonicValidator().IsValid(mnemonic)
    # Same but specifying the language
    is_valid = ElectrumV1MnemonicValidator(ElectrumV1Languages.ENGLISH).IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        ElectrumV1MnemonicValidator().Validate(mnemonic)
        # Valid...
    except ValueError:
        # Invalid length or language...
        pass
    
    # Use ElectrumV1MnemonicDecoder to get back the entropy bytes from a mnemonic, specifying the language
    entropy_bytes = ElectrumV1MnemonicDecoder(ElectrumV1Languages.ENGLISH).Decode(mnemonic)
    # Like before with automatic language detection
    entropy_bytes = ElectrumV1MnemonicDecoder().Decode(mnemonic)

**Code example (mnemonic seed generation)**

The generated seed can be used to construct a `ElectrumV1` class, see the
[related paragraph](https://github.com/ebellocchia/bip_utils/tree/master/readme/eletrum.md).

    from bip_utils import ElectrumV1Languages, ElectrumV1WordsNum, ElectrumV1MnemonicGenerator, ElectrumV1SeedGenerator
    
    # Mnemonic can be generated with ElectrumV1MnemonicGenerator
    mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
    # Or it can be a string
    mnemonic = "like like like like like like like like like like like like"
    
    # Generate with automatic language detection
    # Like before, the mnemonic can be a string or a Mnemonic object
    seed_bytes = ElectrumV1SeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = ElectrumV1SeedGenerator(mnemonic, ElectrumV1Languages.ENGLISH).Generate()
