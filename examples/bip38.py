"""Example of private key encryption/decryption using BIP38."""

from bip_utils import Bip38Decrypter, Bip38Encrypter, WifDecoder, WifEncoder

priv_key_wif = "Kx2nc8CerNfcsutaet3rPwVtxQvXuQTYxw1mSsfFHsWExJ9xVpLf"
passphrase = "DummyPassphrase"

# Decode WIF
priv_key_bytes, _ = WifDecoder.Decode(priv_key_wif)

# Encrypt without EC multiplication
priv_key_enc = Bip38Encrypter.EncryptNoEc(priv_key_bytes, passphrase)
print(f"Encrypted private key: {priv_key_enc}")

# Decrypt without EC multiplication
priv_key_dec = Bip38Decrypter.DecryptNoEc(priv_key_enc, passphrase)
print(f"Decrypted private key: {WifEncoder.Encode(priv_key_dec)}")
