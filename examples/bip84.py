"""Example of keys derivation using BIP84."""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44Changes, Bip84, Bip84Coins


ADDR_NUM: int = 5

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

# Derive BIP84 account keys: m/84'/0'/0'
bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)
# Derive BIP84 chain keys: m/84'/0'/0'/0
bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Derive addresses: m/84'/0'/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address public key (extended): {bip84_addr_ctx.PublicKey().ToExtended()}")
    print(f"  {i}. Address private key (extended): {bip84_addr_ctx.PrivateKey().ToExtended()}")
    print(f"  {i}. Address: {bip84_addr_ctx.PublicKey().ToAddress()}")
