"""Example of keys derivation for Monero (same addresses of official wallet)."""

import binascii

from bip_utils import Monero, MoneroMnemonicGenerator, MoneroSeedGenerator, MoneroWordsNum


# Generate random mnemonic
mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = MoneroSeedGenerator(mnemonic).Generate()

# Construct from seed
monero = Monero.FromSeed(seed_bytes)

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
