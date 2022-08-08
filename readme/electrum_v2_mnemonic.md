## Electrum V2 mnemonics

Electrum V2 mnemonics are the current mnemonic type used by Electrum.\
There 4 type of V2 mnemonics (all supported):
- Standard
- Segwit
- Standard 2FA
- Segwit 2FA

The usage of the Electrum V2 mnemonic library is basically equivalent to the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one,
just replace the `Bip39` prefix with `ElectrumV2`.

### Mnemonic generation

Supported words number:

|Words number|Enum|
|---|---|
|12|`ElectrumV2WordsNum.WORDS_NUM_12`|
|24|`ElectrumV2WordsNum.WORDS_NUM_24`|

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|132|`ElectrumV2EntropyBitLen.BIT_LEN_132`|
|264|`ElectrumV2EntropyBitLen.BIT_LEN_264`|

Supported languages:

|Language|Enum|
|---|---|
|Chinese Simplified|`ElectrumV2Languages.CHINESE_SIMPLIFIED`|
|English|`ElectrumV2Languages.ENGLISH`|
|Portuguese|`ElectrumV2Languages.PORTUGUESE`|
|Spanish|`ElectrumV2Languages.SPANISH`|

Supported mnemonic types:

|Mnemonic type|Enum|
|---|---|
|Standard|`ElectrumV2MnemonicTypes.STANDARD`|
|Segwit|`ElectrumV2MnemonicTypes.SEGWIT`|
|Standard 2FA|`ElectrumV2MnemonicTypes.STANDARD_2FA`|
|Segwit 2FA|`ElectrumV2MnemonicTypes.SEGWIT_2FA`|

With respect to BIP-0039, the desired mnemonic type shall be specified when generating or encoding a mnemonic.

Please note that, because of the generation algorithm used by Electrum:
- When using `ElectrumV2MnemonicGenerator`:
    - When generating a mnemonic from entropy bytes, the specified entropy is only a starting point for finding a suitable 
one for generating a mnemonic. Therefore, it's very likely that the actual entropy bytes will be different.
To get the actual entropy bytes, just decode the generated mnemonic.
    - Depending on the number of attempts to find a suitable entropy, the mnemonic generation can be faster or slower.
    - The bits of the big endian integer encoded by the entropy bytes shall be at least 121 (for 12 words) or 253 (for 24 words). 
Otherwise, a mnemonic generation is not possible and a ValueError exception will be raised.
- When using `ElectrumV2MnemonicEncoder`:
    - The specified entropy bytes are directly used to generate the mnemonic, without trying different ones if not suitable.
Therefore, `ValueError` will be raised if the entropy bytes are not suitable for generating a valid mnemonic.

**Code example**

    import binascii
    from bip_utils import (
        ElectrumV2EntropyBitLen, ElectrumV2EntropyGenerator, ElectrumV2Languages, ElectrumV2MnemonicTypes,
        ElectrumV2WordsNum, ElectrumV2MnemonicEncoder, ElectrumV2MnemonicGenerator
    )
    
    # Generate a random mnemonic string of 12 words, standard type, with default language (English)
    # A Mnemonic object will be returned
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
    
    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())
    
    # Generate a random mnemonic string of 24 words, segwit type, by specifying the language
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT,
                                           ElectrumV2Languages.ENGLISH).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_24)
    
    # Generate the mnemonic string from entropy bytes
    entropy_bytes = binascii.unhexlify(b"06ef0f730072f307c3bda36f71e483fb9e")
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD_2FA).FromEntropy(entropy_bytes)
    
    # Generate mnemonic from random 132-bit entropy
    entropy_bytes = ElectrumV2EntropyGenerator(ElectrumV2EntropyBitLen.BIT_LEN_132).Generate()
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT_2FA).FromEntropy(entropy_bytes)
    
    # Alternatively, the mnemonic can be generated from entropy using the encoder
    # If the entropy bytes are not suitable for generating a mnemonic, ValueError will be raised
    try:
        mnemonic = ElectrumV2MnemonicEncoder(ElectrumV2MnemonicTypes.STANDARD, ElectrumV2Languages.ENGLISH).Encode(entropy_bytes)
        mnemonic = ElectrumV2MnemonicEncoder(ElectrumV2MnemonicTypes.STANDARD).Encode(entropy_bytes)
    except ValueError:
        pass
    
    # Entropy with not enough bits, raises ValueError
    try:
        entropy_bytes = binascii.unhexlify(b"00000000000000000000000000000000")
        mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy(entropy_bytes)
    except ValueError:
        pass

### Mnemonic validation

With respect to BIP-0039, the desired mnemonic type can be specified when validating or encoding a mnemonic.
If `None`, any valid mnemonic type will be accepted.\
For `ElectrumV2MnemonicValidator.Validate` and `ElectrumV2MnemonicDecoder`, `ValueError` will be raised in case
the mnemonic type is not existent of it's different to the specified one,

**Code example**
    
    from bip_utils import (
        ElectrumV2Languages, ElectrumV2MnemonicTypes, ElectrumV2WordsNum, ElectrumV2Mnemonic,
        ElectrumV2MnemonicGenerator, ElectrumV2MnemonicValidator, ElectrumV2MnemonicDecoder,
    )
    
    # Mnemonic can be generated with ElectrumV2MnemonicGenerator
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
    # Or it can be a string
    mnemonic = "buddy immune recycle material point hotel easily order diesel globe differ awkward"
    # Or from a list
    mnemonic = ElectrumV2Mnemonic.FromList(mnemonic.split())
    
    # Get if a mnemonic is valid, accepting any mnemonic type, return bool
    # The mnemonic can be a string or a Mnemonic object
    is_valid = ElectrumV2MnemonicValidator().IsValid(mnemonic)
    # Same but specifying the language
    is_valid = ElectrumV2MnemonicValidator(lang=ElectrumV2Languages.ENGLISH).IsValid(mnemonic)
    # Validate a mnemonic, accepting any mnemonic type, raise exceptions
    try:
        ElectrumV2MnemonicValidator().Validate(mnemonic)
        # Valid...
    except ValueError:
        # Invalid length, language or mnemonic type...
        pass
    
    # Like before but accepting only the specified mnemonic type
    is_valid = ElectrumV2MnemonicValidator(ElectrumV2MnemonicTypes.STANDARD).IsValid(mnemonic)
    is_valid = ElectrumV2MnemonicValidator(ElectrumV2MnemonicTypes.STANDARD, ElectrumV2Languages.ENGLISH).IsValid(mnemonic)
    try:
        ElectrumV2MnemonicValidator(ElectrumV2MnemonicTypes.STANDARD).Validate(mnemonic)
        # Valid...
    except ValueError:
        # Invalid length, language or mnemonic type...
        pass
    
    # Use ElectrumV2MnemonicDecoder to get back the entropy bytes from a mnemonic
    # Accepting any mnemonic type, specifying the language
    try:
        entropy_bytes = ElectrumV2MnemonicDecoder(lang=ElectrumV2Languages.ENGLISH).Decode(mnemonic)
    except ValueError:
        # Invalid mnemonic type...
        pass
    # Like before with automatic language detection
    entropy_bytes = ElectrumV2MnemonicDecoder().Decode(mnemonic)
    # Like before but accepting only the specified mnemonic type
    entropy_bytes = ElectrumV2MnemonicDecoder(ElectrumV2MnemonicTypes.STANDARD, ElectrumV2Languages.ENGLISH).Decode(mnemonic)
    entropy_bytes = ElectrumV2MnemonicDecoder(ElectrumV2MnemonicTypes.STANDARD).Decode(mnemonic)

### Seed generation

The generated seed can be used to construct a `ElectrumV2` classes, see the
[related paragraph](https://github.com/ebellocchia/bip_utils/tree/master/readme/eletrum.md).

**Code example**

    from bip_utils import (
        ElectrumV2Languages, ElectrumV2MnemonicTypes, ElectrumV2WordsNum, ElectrumV2MnemonicGenerator, ElectrumV2SeedGenerator
    )
    
    # Mnemonic can be generated with ElectrumV2MnemonicGenerator
    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
    # Or it can be a string
    mnemonic = "buddy immune recycle material point hotel easily order diesel globe differ awkward"
    
    # Generate with automatic language detection and passphrase (empty)
    # Like before, the mnemonic can be a string or a Mnemonic object
    seed_bytes = ElectrumV2SeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = ElectrumV2SeedGenerator(mnemonic, ElectrumV2Languages.ENGLISH).Generate()
