"""Example of keys computation using brainwallet module with default algorithms."""

from bip_utils import Brainwallet, BrainwalletAlgos, BrainwalletCoins


# Passphrase chosen by user
passphrase = "The quick brown fox jumps over the lazy dog"

# SHA256
brainwallet_sha256 = Brainwallet.Generate(
    passphrase,
    BrainwalletCoins.BITCOIN,
    BrainwalletAlgos.SHA256
)

print("** SHA256 **")
print(f"Private key: {brainwallet_sha256.PrivateKey().Raw().ToHex()}")
print(f"Public key: {brainwallet_sha256.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {brainwallet_sha256.PublicKey().ToAddress()}")

# Double SHA256
brainwallet_sha256 = Brainwallet.Generate(
    passphrase,
    BrainwalletCoins.BITCOIN,
    BrainwalletAlgos.DOUBLE_SHA256
)

print("** DOUBLE SHA256 **")
print(f"Private key: {brainwallet_sha256.PrivateKey().Raw().ToHex()}")
print(f"Public key: {brainwallet_sha256.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {brainwallet_sha256.PublicKey().ToAddress()}")

# PBKDF2 HMAC-SHA512
brainwallet_sha256 = Brainwallet.Generate(
    passphrase,
    BrainwalletCoins.BITCOIN,
    BrainwalletAlgos.PBKDF2_HMAC_SHA512
)

print("** PBKDF2 HMAC-SHA512 **")
print(f"Private key: {brainwallet_sha256.PrivateKey().Raw().ToHex()}")
print(f"Public key: {brainwallet_sha256.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {brainwallet_sha256.PublicKey().ToAddress()}")

# Scrypt
brainwallet_sha256 = Brainwallet.Generate(
    passphrase,
    BrainwalletCoins.BITCOIN,
    BrainwalletAlgos.SCRYPT
)

print("** Scrypt **")
print(f"Private key: {brainwallet_sha256.PrivateKey().Raw().ToHex()}")
print(f"Public key: {brainwallet_sha256.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {brainwallet_sha256.PublicKey().ToAddress()}")
