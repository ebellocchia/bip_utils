## BIP-0038 library

The BIP-0038 library allows encrypting/decrypting private keys as defined by [BIP-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki).

It supports both private keys encryption/decryption with and without EC multiplication.

**Code example (without EC multiplication)**

    import binascii
    from bip_utils import Bip38PubKeyModes, Bip38Decrypter, Bip38Encrypter, Secp256k1PrivateKey
    
    passphrase = "DummyPassphrase"
    
    # Private key bytes or a private key object can be used
    priv_key = binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67')
    priv_key = Secp256k1PrivateKey.FromBytes(
        binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67'))
    
    # Encrypt without EC multiplication (compressed public key)
    enc = Bip38Encrypter.EncryptNoEc(priv_key, passphrase, Bip38PubKeyModes.COMPRESSED)
    print(enc)
    
    # Decrypt without EC multiplication
    dec, pub_key_mode = Bip38Decrypter.DecryptNoEc(enc, passphrase)
    print(binascii.hexlify(dec))
    
    # Encrypt without EC multiplication (uncompressed public key)
    enc = Bip38Encrypter.EncryptNoEc(priv_key, passphrase, Bip38PubKeyModes.UNCOMPRESSED)
    print(enc)
    
    # Decrypt without EC multiplication
    dec, pub_key_mode = Bip38Decrypter.DecryptNoEc(enc, passphrase)
    print(binascii.hexlify(dec))

**Code example (with EC multiplication)**

    import binascii
    from bip_utils import Bip38PubKeyModes, Bip38Decrypter, Bip38Encrypter, Bip38EcKeysGenerator
    
    passphrase = "DummyPassphrase"
    
    # Use EC multiplication to generate an intermediate passphrase without lot and sequence numbers
    int_pass = Bip38EcKeysGenerator.GenerateIntermediatePassphrase(passphrase)
    print(int_pass)
    # Use EC multiplication to generate an encrypted private key from the intermediate passphrase
    enc = Bip38EcKeysGenerator.GeneratePrivateKey(int_pass, Bip38PubKeyModes.COMPRESSED)
    print(enc)
    
    # Decrypt with EC multiplication
    dec, pub_key_mode = Bip38Decrypter.DecryptEc(enc, passphrase)
    print(binascii.hexlify(dec))
    
    # Use EC multiplication to generate an intermediate passphrase with lot and sequence numbers
    int_pass = Bip38EcKeysGenerator.GenerateIntermediatePassphrase(passphrase,
                                                                   lot_num=100000,
                                                                   sequence_num=1)
    print(int_pass)
    # Use EC multiplication to generate an encrypted private key from the intermediate passphrase
    enc = Bip38EcKeysGenerator.GeneratePrivateKey(int_pass, Bip38PubKeyModes.UNCOMPRESSED)
    print(enc)
    
    # Decrypt with EC multiplication
    dec, pub_key_mode = Bip38Decrypter.DecryptEc(enc, passphrase)
    print(binascii.hexlify(dec))
    
    # Or, you can use Bip38Encrypter for generating keys with EC multiplication in one-shot
    enc = Bip38Encrypter.GeneratePrivateKeyEc(passphrase,
                                              Bip38PubKeyModes.COMPRESSED,
                                              lot_num=100000,
                                              sequence_num=1)
    print(enc)
