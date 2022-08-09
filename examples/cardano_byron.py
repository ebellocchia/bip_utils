"""Example of key derivation for Cardano (Byron addresses)."""

import binascii

from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Changes, Bip44Coins, CardanoByronLegacy,
    CardanoByronLegacySeedGenerator, CardanoIcarusSeedGenerator
)


ADDR_NUM: int = 5

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
print(f"Mnemonic string: {mnemonic}")

#
# Cardano Byron (legacy)
#

print("")
print("Byron-Legacy")
print("")

# Generate seed from mnemonic
seed_bytes = CardanoByronLegacySeedGenerator(mnemonic).Generate()
# Construct from seed
byron_legacy = CardanoByronLegacy.FromSeed(seed_bytes)
# Print HD path key
print(f"HD path key (bytes): {binascii.hexlify(byron_legacy.HdPathKey())}")
# Print master key
print(f"Master chain code (bytes): {byron_legacy.MasterPrivateKey().ChainCode().ToHex()}")
print(f"Master private key (bytes): {byron_legacy.MasterPrivateKey().Raw().ToHex()}")

# Derive address keys: m/0'/i'
print("Address keys:")
for i in range(ADDR_NUM):
    print(f"  {i}. Address chain code (bytes): {byron_legacy.GetPrivateKey(0, i).ChainCode().ToHex()}")
    print(f"  {i}. Address private key (bytes): {byron_legacy.GetPrivateKey(0, i).Raw().ToHex()}")
    print(f"  {i}. Address: {byron_legacy.GetAddress(0, i)}")
    print(f"  {i}. Derivation path: {byron_legacy.HdPathFromAddress(byron_legacy.GetAddress(0, i))}")

#
# Cardano Byron (Icarus)
#

print("")
print("Byron-Icarus")
print("")

# Generate seed from mnemonic
seed_bytes = CardanoIcarusSeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO_BYRON_ICARUS)
# Print master key
print(f"Master chain code (bytes): {bip44_mst_ctx.PrivateKey().ChainCode().ToHex()}")
print(f"Master private key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive chain keys: m/44'/1815'/0'/0
bip44_chg_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)

# Derive addresses: m/44'/1815'/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address chain code (bytes): {bip44_addr_ctx.PublicKey().ChainCode().ToHex()}")
    print(f"  {i}. Address public key (bytes): {bip44_addr_ctx.PublicKey().RawCompressed().ToHex()[2:]}")
    print(f"  {i}. Address private key (bytes): {bip44_addr_ctx.PrivateKey().Raw().ToHex()}")
    print(f"  {i}. Address: {bip44_addr_ctx.PublicKey().ToAddress()}")

#
# Cardano Byron (Ledger)
#

print("")
print("Byron-Ledger")
print("")

# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO_BYRON_LEDGER)
# Print master key
print(f"Master chain code (bytes): {bip44_mst_ctx.PrivateKey().ChainCode().ToHex()}")
print(f"Master private key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive chain keys: m/44'/1815'/0'/0
bip44_chg_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)

# Derive addresses: m/44'/1815'/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address chain code (bytes): {bip44_addr_ctx.PublicKey().ChainCode().ToHex()}")
    print(f"  {i}. Address public key (bytes): {bip44_addr_ctx.PublicKey().RawCompressed().ToHex()[2:]}")
    print(f"  {i}. Address private key (bytes): {bip44_addr_ctx.PrivateKey().Raw().ToHex()}")
    print(f"  {i}. Address: {bip44_addr_ctx.PublicKey().ToAddress()}")
