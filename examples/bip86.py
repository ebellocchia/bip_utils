"""Example of keys derivation using BIP86."""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44Changes, Bip86, Bip86Coins


ADDR_NUM: int = 5

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip86_mst_ctx = Bip86.FromSeed(seed_bytes, Bip86Coins.BITCOIN)
# Print master key
print(f"Master key (bytes): {bip86_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip86_mst_ctx.PrivateKey().ToExtended()}")
print(f"Master key (WIF): {bip86_mst_ctx.PrivateKey().ToWif()}")

# Derive BIP86 account keys: m/86'/0'/0'
bip86_acc_ctx = bip86_mst_ctx.Purpose().Coin().Account(0)
# Derive BIP86 chain keys: m/86'/0'/0'/0
bip86_chg_ctx = bip86_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

# Derive addresses: m/86'/0'/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    bip86_addr_ctx = bip86_chg_ctx.AddressIndex(i)
    print(f"  {i}. Address public key (extended): {bip86_addr_ctx.PublicKey().ToExtended()}")
    print(f"  {i}. Address private key (extended): {bip86_addr_ctx.PrivateKey().ToExtended()}")
    print(f"  {i}. Address: {bip86_addr_ctx.PublicKey().ToAddress()}")
