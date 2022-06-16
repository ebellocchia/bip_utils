## Algorand mnemonic library

The official Algorand wallet uses a 25-word mnemonic, which is generated with a different algorithm with respect to BIP-0039, 
even if the words list is the same.

The functionalities of this library are the same of the BIP-0039 one but with Algorand-style mnemonics:
- Generate mnemonics from words number or entropy bytes
- Validate a mnemonic
- Get back the entropy bytes from a mnemonic
- Generate the seed from a mnemonic

### Library usage

The usage of the Algorand mnemonic library is basically equivalent to the [BIP-0039](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip39.md) one,
just replace the *Bip39* prefix with *Algorand*.

Supported words number:

|Words number|Enum|
|---|---|
|25|*AlgorandWordsNum.WORDS_NUM_25*|

Supported entropy bits:

|Entropy bits|Enum|
|---|---|
|256|*AlgorandEntropyBitLen.BIT_LEN_256*|

Supported languages:

|Language|Enum|
|---|---|
|English|*AlgorandLanguages.ENGLISH*|

**Code example**

    import binascii
    from bip_utils import (
        MnemonicChecksumError, AlgorandEntropyBitLen, AlgorandEntropyGenerator, AlgorandLanguages, AlgorandWordsNum,
        AlgorandMnemonicDecoder, AlgorandMnemonicEncoder,
        AlgorandMnemonicGenerator, AlgorandMnemonicValidator, AlgorandSeedGenerator
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
    
    # Generate mnemonic from random 256-bit entropy (with and without checksum)
    entropy_bytes = AlgorandEntropyGenerator(AlgorandEntropyBitLen.BIT_LEN_256).Generate()
    mnemonic = AlgorandMnemonicGenerator().FromEntropy(entropy_bytes)
    
    # Alternatively, the mnemonic can be generated from entropy using the encoder
    mnemonic = AlgorandMnemonicEncoder(AlgorandLanguages.ENGLISH).Encode(entropy_bytes)
    
    # Get if a mnemonic is valid, return bool
    # The mnemonic can be a string or a Mnemonic object
    is_valid = AlgorandMnemonicValidator().IsValid(mnemonic)
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
    
    # Generate with automatic language detection and passphrase (empty)
    # Like before, the mnemonic can be a string or a Mnemonic object
    seed_bytes = AlgorandSeedGenerator(mnemonic).Generate()
    # Generate specifying the language
    seed_bytes = AlgorandSeedGenerator(mnemonic, AlgorandLanguages.ENGLISH).Generate()