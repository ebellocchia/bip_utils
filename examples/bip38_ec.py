"""Example of private key encryption/decryption with EC multiplication using BIP38."""

import binascii

from bip_utils import Bip38Decrypter, Bip38EcKeysGenerator, Bip38Encrypter, Bip38PubKeyModes, WifEncoder


# BIP38 passphrase
passphrase = "DummyPassphrase"

# Generate an intermediate passphrase without lot and sequence numbers
int_pass = Bip38EcKeysGenerator.GenerateIntermediatePassphrase(passphrase)
print(f"Intermediate passphrase: {int_pass}")
# Generate an encrypted private key from the intermediate passphrase
priv_key_enc = Bip38EcKeysGenerator.GeneratePrivateKey(int_pass, Bip38PubKeyModes.COMPRESSED)
print(f"Encrypted private key (no lot/sequence): {priv_key_enc}")
# Decrypt
priv_key_dec, pub_key_mode = Bip38Decrypter.DecryptEc(priv_key_enc, passphrase)
print(f"Decrypted private key (bytes): {binascii.hexlify(priv_key_dec)}")
print(f"Decrypted private key (WIF): {WifEncoder.Encode(priv_key_dec, pub_key_mode=pub_key_mode)}")


# Generate an intermediate passphrase with lot and sequence numbers
int_pass = Bip38EcKeysGenerator.GenerateIntermediatePassphrase(passphrase,
                                                               lot_num=100000,
                                                               sequence_num=1)
print(f"Intermediate passphrase: {int_pass}")
# Generate an encrypted private key from the intermediate passphrase
priv_key_enc = Bip38EcKeysGenerator.GeneratePrivateKey(int_pass, Bip38PubKeyModes.UNCOMPRESSED)
print(f"Encrypted private key (with lot/sequence): {priv_key_enc}")
# Decrypt
priv_key_dec, pub_key_mode = Bip38Decrypter.DecryptEc(priv_key_enc, passphrase)
print(f"Decrypted private key (bytes): {binascii.hexlify(priv_key_dec)}")
print(f"Decrypted private key (WIF): {WifEncoder.Encode(priv_key_dec, pub_key_mode=pub_key_mode)}")


# Or, you can use Bip38Encrypter for generating keys in one-shot
priv_key_enc = Bip38Encrypter.GeneratePrivateKeyEc(passphrase,
                                                   Bip38PubKeyModes.COMPRESSED,
                                                   lot_num=100000,
                                                   sequence_num=1)
print(f"Encrypted private key (with Bip38Encrypter): {priv_key_enc}")
# Decrypt
priv_key_dec, pub_key_mode = Bip38Decrypter.DecryptEc(priv_key_enc, passphrase)
print(f"Decrypted private key (bytes): {binascii.hexlify(priv_key_dec)}")
print(f"Decrypted private key (WIF): {WifEncoder.Encode(priv_key_dec, pub_key_mode=pub_key_mode)}")
