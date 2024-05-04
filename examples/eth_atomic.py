"""
Example of how to get Ethereum address like Atomic wallet.

Atomic Wallet doesn't actually derive a BIP44 path for Ethereum, but it directly uses the master key for getting the address.
"""

from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins


# Mnemonic
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
# Print master key
print(f"Private key: {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Address: {bip44_mst_ctx.PublicKey().ToAddress()}")
