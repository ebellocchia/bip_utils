"""Example of private key encryption/decryption without EC multiplication using BIP38."""

import binascii

from bip_utils import Bip38Decrypter, Bip38Encrypter, WifDecoder, WifEncoder


# BIP38 passphrase
passphrase = "DummyPassphrase"

# WIF private key correspondent to a compressed public key
priv_key_wif = "Kx2nc8CerNfcsutaet3rPwVtxQvXuQTYxw1mSsfFHsWExJ9xVpLf"

# Decode WIF
priv_key_bytes, pub_key_mode = WifDecoder.Decode(priv_key_wif)

# Encrypt (compressed public key)
# Bip38PubKeyModes is an alias for WifPubKeyModes so it can be passed directly as a parameter
priv_key_enc = Bip38Encrypter.EncryptNoEc(priv_key_bytes, passphrase, pub_key_mode)
print(f"Encrypted private key (compressed public key): {priv_key_enc}")

# Decrypt
priv_key_dec, pub_key_mode = Bip38Decrypter.DecryptNoEc(priv_key_enc, passphrase)
print(f"Decrypted private key (bytes): {binascii.hexlify(priv_key_dec)}")
print(f"Decrypted private key (WIF): {WifEncoder.Encode(priv_key_dec, pub_key_mode=pub_key_mode)}")

# WIF private key correspondent to an uncompressed public key
priv_key_wif = "5HzxC8XHHAtoC5jVvScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr"

# Decode WIF
priv_key_bytes, pub_key_mode = WifDecoder.Decode(priv_key_wif)

# Encrypt (uncompressed public key)
priv_key_enc = Bip38Encrypter.EncryptNoEc(priv_key_bytes, passphrase, pub_key_mode)
print(f"Encrypted private key (uncompressed public key): {priv_key_enc}")

# Decrypt
priv_key_dec, pub_key_mode = Bip38Decrypter.DecryptNoEc(priv_key_enc, passphrase)
print(f"Decrypted private key (bytes): {binascii.hexlify(priv_key_dec)}")
print(f"Decrypted private key (WIF): {WifEncoder.Encode(priv_key_dec, pub_key_mode=pub_key_mode)}")
