"""Example of key derivation for Cardano (Shelley addresses)."""
"""Example of key derivation for Cardano (Byron addresses)."""

from bip_utils import (
    Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator,
    Bip44Changes, Cip1852Coins, CardanoIcarusSeedGenerator, CardanoShelley, Cip1852
)

ADDR_NUM: int = 5

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_15)
print(f"Mnemonic string: {mnemonic}")

#
# Cardano Shelley (Icarus)
#

print("")
print("Shelley-Icarus")
print("")

# Generate seed from mnemonic
seed_bytes = CardanoIcarusSeedGenerator(mnemonic).Generate()

# Construct from seed
cip1852_mst_ctx = Cip1852.FromSeed(seed_bytes, Cip1852Coins.CARDANO_ICARUS)
# Print master key
print(f"Master chain code (bytes): {cip1852_mst_ctx.PrivateKey().Bip32Key().Data().ChainCode().ToHex()}")
print(f"Master private key (bytes): {cip1852_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive account keys and construct CardanoShelley
shelley_acc_ctx = CardanoShelley.FromCip1852Object(
    cip1852_mst_ctx.Purpose().Coin().Account(0)
)

# Print staking address
print(f"Staking address: {shelley_acc_ctx.StakingObject().PublicKey().ToAddress()}")

# Derive external chain
shelley_chg_ctx = shelley_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Derive addresses
print("Addresses:")
for i in range(ADDR_NUM):
    shelley_addr_ctx = shelley_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address chain code (bytes): {shelley_addr_ctx.PublicKeys().AddressKey().Data().ChainCode().ToHex()}")
    print(f"  {i}. Address public key (bytes): {shelley_addr_ctx.PublicKeys().AddressKey().RawCompressed().ToHex()[2:]}")
    print(f"  {i}. Address private key (bytes): {shelley_addr_ctx.PrivateKeys().AddressKey().Raw().ToHex()}")
    print(f"  {i}. Address: {shelley_addr_ctx.PublicKeys().ToAddress()}")

#
# Cardano Shelley (Ledger)
#

print("")
print("Shelley-Ledger")
print("")

# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
cip1852_mst_ctx = Cip1852.FromSeed(seed_bytes, Cip1852Coins.CARDANO_LEDGER)
# Print master key
print(f"Master chain code (bytes): {cip1852_mst_ctx.PrivateKey().Bip32Key().Data().ChainCode().ToHex()}")
print(f"Master private key (bytes): {cip1852_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive account keys and construct CardanoShelley
shelley_acc_ctx = CardanoShelley.FromCip1852Object(
    cip1852_mst_ctx.Purpose().Coin().Account(0)
)

# Print staking address
print(f"Staking address: {shelley_acc_ctx.StakingObject().PublicKey().ToAddress()}")

# Derive external chain
shelley_chg_ctx = shelley_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Derive addresses
print("Addresses:")
for i in range(ADDR_NUM):
    shelley_addr_ctx = shelley_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address chain code (bytes): {shelley_addr_ctx.PublicKeys().AddressKey().Data().ChainCode().ToHex()}")
    print(f"  {i}. Address public key (bytes): {shelley_addr_ctx.PublicKeys().AddressKey().RawCompressed().ToHex()[2:]}")
    print(f"  {i}. Address private key (bytes): {shelley_addr_ctx.PrivateKeys().AddressKey().Raw().ToHex()}")
    print(f"  {i}. Address: {shelley_addr_ctx.PublicKeys().ToAddress()}")