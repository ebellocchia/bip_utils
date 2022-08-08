## Algorand mnemonic library

The official Algorand wallet uses a 25-word mnemonic, which is generated with a different algorithm with respect to BIP-0039, 
even if the words list is the same.

The functionalities of this library are the same of the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one but with Algorand-style mnemonics:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

### Library usage

The usage of the Algorand mnemonic library is basically equivalent to the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one,
just replace the `Bip39` prefix with `Algorand`.

Supported words number:

|Words number|Enum|
|---|---|
|25|`AlgorandWordsNum.WORDS_NUM_25`|

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|256|`AlgorandEntropyBitLen.BIT_LEN_256`|

Supported languages:

|Language|Enum|
|---|---|
|English|`AlgorandLanguages.ENGLISH`|

**Code example (mnemonic generation)**

    import binascii
    from bip_utils import (
        AlgorandEntropyBitLen, AlgorandEntropyGenerator, AlgorandLanguages, AlgorandWordsNum,
        AlgorandMnemonicEncoder, AlgorandMnemonicGenerator
    )
    
    # Generate a random mnemonic string of 25 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = AlgorandMnemonicGenerator().FromWordsNumber(AlgorandWordsNum.WORDS_NUM_25)
    
    # Get words count
    print(mnemonic.WordsCount())
    # Get as string
    print(mnemonic.ToStr())
    print(str(mnemonic))
    # Get as list of strings
    print(mnemonic.ToList())
    
    # Generate a random mnemonic string of 25 words by specifying the language
    mnemonic = AlgorandMnemonicGenerator(AlgorandLanguages.ENGLISH).FromWordsNumber(AlgorandWordsNum.WORDS_NUM_25)
    
    # Generate the mnemonic string from entropy bytes
    entropy_bytes = binascii.unhexlify(b"0000000000000000000000000000000000000000000000000000000000000000")
    mnemonic = AlgorandMnemonicGenerator().FromEntropy(entropy_bytes)
    
    # Generate mnemonic from random 256-bit entropy
    entropy_bytes = AlgorandEntropyGenerator(AlgorandEntropyBitLen.BIT_LEN_256).Generate()
    mnemonic = AlgorandMnemonicGenerator().FromEntropy(entropy_bytes)
    
    # Alternatively, the mnemonic can be generated from entropy using the encoder
    mnemonic = AlgorandMnemonicEncoder(AlgorandLanguages.ENGLISH).Encode(entropy_bytes)
    mnemonic = AlgorandMnemonicEncoder().Encode(entropy_bytes)

**Code example (mnemonic validation)**

    from bip_utils import (
        MnemonicChecksumError, AlgorandLanguages, AlgorandWordsNum, AlgorandMnemonic,
        AlgorandMnemonicGenerator, AlgorandMnemonicValidator, AlgorandMnemonicDecoder,
    )
    
    # Mnemonic can be generated with AlgorandMnemonicGenerator
    mnemonic = AlgorandMnemonicGenerator().FromWordsNumber(AlgorandWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"
    # Or from a list
    mnemonic = AlgorandMnemonic.FromList(mnemonic.split())
    
    # Get if a mnemonic is valid with automatic language detection, return bool
    is_valid = AlgorandMnemonicValidator().IsValid(mnemonic)
    # Same but specifying the language
    is_valid = AlgorandMnemonicValidator(AlgorandLanguages.ENGLISH).IsValid(mnemonic)
    # Validate a mnemonic, raise exceptions
    try:
        AlgorandMnemonicValidator().Validate(mnemonic)
        # Valid...
    except MnemonicChecksumError:
        # Invalid checksum...
        pass
    except ValueError:
        # Invalid length or language...
        pass
    
    # Use AlgorandMnemonicDecoder to get back the entropy bytes from a mnemonic, specifying the language
    entropy_bytes = AlgorandMnemonicDecoder(AlgorandLanguages.ENGLISH).Decode(mnemonic)
    # Like before with automatic language detection
    entropy_bytes = AlgorandMnemonicDecoder().Decode(mnemonic)

**Code example (mnemonic seed generation)**

    from bip_utils import AlgorandLanguages, AlgorandWordsNum, AlgorandMnemonicGenerator, AlgorandSeedGenerator
    
    # Mnemonic can be generated with AlgorandMnemonicGenerator
    mnemonic = AlgorandMnemonicGenerator().FromWordsNumber(AlgorandWordsNum.WORDS_NUM_25)
    # Or it can be a string
    mnemonic = "pizza stereo depth shallow skill lucky delay base tree barrel capital knife sure era harvest eye retreat raven mammal oxygen impulse defense loud absorb giggle"
    
    # Generate with automatic language detection
    # Like before, the mnemonic can be a string or a Mnemonic object
    seed_bytes = AlgorandSeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = AlgorandSeedGenerator(mnemonic, AlgorandLanguages.ENGLISH).Generate()
