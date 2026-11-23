"""Example of Shamir's secret sharing of a wallet seed using SLIP39."""

import itertools

from bip_utils import Bip44, Bip44Changes, Bip44Coins, Slip39MnemonicGenerator, Slip39SeedGenerator, Slip39WordsNum


# Passphrase protecting the master secret (optional)
PASSPHRASE = "my passphrase"

# 2 groups out of 3 are needed to recover the master secret:
# - Group 0: a single share (e.g. kept by the owner)
# - Group 1: 2 shares out of 3 (e.g. friends)
# - Group 2: 3 shares out of 5 (e.g. family)
groups = Slip39MnemonicGenerator(group_threshold=2,
                                 groups=[(1, 1), (2, 3), (3, 5)]).FromWordsNumber(Slip39WordsNum.WORDS_NUM_20,
                                                                                  PASSPHRASE)
for group_idx, group in enumerate(groups):
    print(f"Group {group_idx}:")
    for mnemonic in group:
        print(f"  {mnemonic}")

# Recover the seed with group 0 and 2 shares of group 1
seed_bytes = Slip39SeedGenerator(groups[0] + groups[1][:2]).Generate(PASSPHRASE)
print(f"Seed: {seed_bytes.hex()}")

# Any other valid combination results in the same seed
for members in itertools.combinations(groups[2], 3):
    assert Slip39SeedGenerator(list(members) + groups[1][1:]).Generate(PASSPHRASE) == seed_bytes

# Extend the backup with a new set of shares (2-of-2 scheme), the passphrase is not needed
new_groups = Slip39MnemonicGenerator(groups=[(2, 2)]).FromMnemonics(groups[0] + groups[2][:3])
assert Slip39SeedGenerator(new_groups[0]).Generate(PASSPHRASE) == seed_bytes

# The seed is a BIP32 seed
bip44_acc_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN).Purpose().Coin().Account(0)
print(f"First address: {bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()}")
