"""Example of keys derivation for Monero based on BIP44."""

import binascii

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Coins, Monero


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP)
# Print master key
print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip44_mst_ctx.PrivateKey().ToExtended()}")

# Derive default path
bip44_def_ctx = bip44_mst_ctx.DeriveDefaultPath()

# Create Monero object from the BIP44 private key
monero = Monero.FromBip44PrivateKey(bip44_def_ctx.PrivateKey().Raw().ToBytes())

# Print keys
print(f"Monero private spend key: {monero.PrivateSpendKey().Raw().ToHex()}")
print(f"Monero private view key: {monero.PrivateViewKey().Raw().ToHex()}")
print(f"Monero public spend key: {monero.PublicSpendKey().RawCompressed().ToHex()}")
print(f"Monero public view key: {monero.PublicViewKey().RawCompressed().ToHex()}")

# Print primary address
print(f"Monero primary address: {monero.PrimaryAddress()}")
# Print integrated address
payment_id = binascii.unhexlify(b"d6f093554c0daa94")
print(f"Monero integrated address: {monero.IntegratedAddress(payment_id)}")
# Print the first 5 subaddresses for account 0 and 1
for acc_idx in range(2):
    for subaddr_idx in range(5):
        print(f"Subaddress (account: {acc_idx}, index: {subaddr_idx}): {monero.Subaddress(subaddr_idx, acc_idx)}")
