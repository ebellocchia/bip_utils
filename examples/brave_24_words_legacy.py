"""
Example of keys derivation with 24-words mnemonic phrase in the same way of Brave crypto wallets extension (legacy).

The old version of Brave crypto wallets extension (now referred as "legacy") worked differently from BIP39 when a 24-words mnemonic phrase was used.
In fact, instead of computing the seed from the mnemonic as described in BIP39, it used the initial entropy directly as seed.
Therefore, the derived keys and addresses were completely different to other wallets.
"""

from bip_utils import Bip39MnemonicDecoder, Bip44, Bip44Changes, Bip44Coins


# Mnemonic
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " \
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

# Get back entropy bytes from mnemonic
entropy_bytes = Bip39MnemonicDecoder().Decode(mnemonic)

# Use the entropy bytes directly as seed
bip44_mst_ctx = Bip44.FromSeed(entropy_bytes, Bip44Coins.ETHEREUM)

# Derive the key of the first address
bip44_addr_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
# Same address of Brave crypto wallets extension
print(f"Address: {bip44_addr_ctx.PublicKey().ToAddress()}")
