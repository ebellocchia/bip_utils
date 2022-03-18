"""Example of key derivation using BIP84."""

from bip_utils import (
    Bip39WordsNum, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Changes, Bip84Coins, Bip84
)

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip84_mst_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
# Print master key
print(f"Master key (bytes): {bip84_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip84_mst_ctx.PrivateKey().ToExtended()}")
print(f"Master key (WIF): {bip84_mst_ctx.PrivateKey().ToWif()}")

# Generate BIP84 account keys: m/84'/0'/0'
bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)
# Generate BIP84 chain keys: m/84'/0'/0'/0
bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Generate the first 10 addresses: m/84'/0'/0'/0/i
for i in range(10):
    bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)
    print(f"{i}. Address public key (extended): {bip84_addr_ctx.PublicKey().ToExtended()}")
    print(f"{i}. Address private key (extended): {bip84_addr_ctx.PrivateKey().ToExtended()}")
    print(f"{i}. Address: {bip84_addr_ctx.PublicKey().ToAddress()}")
