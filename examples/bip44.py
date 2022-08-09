"""Example of keys derivation using BIP44."""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Changes, Bip44Coins


ADDR_NUM: int = 5

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
# Print master key
print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip44_mst_ctx.PrivateKey().ToExtended()}")
print(f"Master key (WIF): {bip44_mst_ctx.PrivateKey().ToWif()}")

# Derive BIP44 account keys: m/44'/0'/0'
bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
# Derive BIP44 chain keys: m/44'/0'/0'/0
bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Derive addresses: m/44'/0'/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address public key (extended): {bip44_addr_ctx.PublicKey().ToExtended()}")
    print(f"  {i}. Address private key (extended): {bip44_addr_ctx.PrivateKey().ToExtended()}")
    print(f"  {i}. Address: {bip44_addr_ctx.PublicKey().ToAddress()}")
