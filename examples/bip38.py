"""Example of private key encryption/decryption using BIP38."""

from bip_utils import Bip38PubKeyModes, Bip38Decrypter, Bip38Encrypter, WifDecoder, WifEncoder

priv_key_wif = "Kx2nc8CerNfcsutaet3rPwVtxQvXuQTYxw1mSsfFHsWExJ9xVpLf"
passphrase = "DummyPassphrase"

# Decode WIF
priv_key_bytes, _ = WifDecoder.Decode(priv_key_wif)

# Encrypt without EC multiplication (compressed public key)
priv_key_enc = Bip38Encrypter.EncryptNoEc(priv_key_bytes, passphrase, Bip38PubKeyModes.COMPRESSED)
print(f"Encrypted private key (compressed public key): {priv_key_enc}")

# Decrypt without EC multiplication
priv_key_dec = Bip38Decrypter.DecryptNoEc(priv_key_enc, passphrase)
print(f"Decrypted private key (from compressed public key): {WifEncoder.Encode(priv_key_dec)}")

# Encrypt without EC multiplication (uncompressed public key)
priv_key_enc = Bip38Encrypter.EncryptNoEc(priv_key_bytes, passphrase, Bip38PubKeyModes.UNCOMPRESSED)
print(f"Encrypted private key (uncompressed public key): {priv_key_enc}")

# Decrypt without EC multiplication
priv_key_dec = Bip38Decrypter.DecryptNoEc(priv_key_enc, passphrase)
print(f"Decrypted private key (from uncompressed public key): {WifEncoder.Encode(priv_key_dec)}")
