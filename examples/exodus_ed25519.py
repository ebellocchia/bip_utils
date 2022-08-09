"""
Example of keys derivation for ed25519-based coins in the same way of Exodus wallet.

Basically, the Exodus wallet uses the secp256k1 curve to derive the complete BIP44 path for all coins, even if they are not based on the secp256k1 curve.
Then, for the coins based on the ed25519 curve (e.g. Algorand, Solana, Stellar, ...), it uses the last derived private key as a ed25519 master key to compute the public key and address.
It's not the only wallet doing this (Atomic Wallet does the same), because in this way the developers don't have to implement other derivation schemes beside secp256k1.
"""

from bip_utils import Bip32Slip10Secp256k1, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44ConfGetter


# Coin that we want
coin_type = Bip44Coins.SOLANA

# Mnemonic
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Get coin index from configuration
coin_idx = Bip44ConfGetter.GetConfig(coin_type).CoinIndex()

# Derive the standard BIP44 path using secp256k1
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes).DerivePath(f"m/44'/{coin_idx}'/0'/0/0")
priv_key_bytes = bip32_ctx.PrivateKey().Raw().ToBytes()

# Use the last private key as a ed25519 master key, we can use Bip44 to simplify the address computation
bip44_ctx = Bip44.FromPrivateKey(priv_key_bytes, coin_type)
# Same address of Exodus
print(f"Address: {bip44_ctx.PublicKey().ToAddress()}")
