"""
Ledger Live derives keys for Ethereum in a different way with respect to Metamask.
Basically, when adding a new account, instead of increasing the address index like Metamask (m/44'/60'/0'/0/i)
it increases the account index by leaving the address index fixed at zero (m/44'/60'/i'/0/0).
The result is that the first address is the same of Metamask, while the next ones are different.
This example shows keys generation like Ledger Live.
"""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Changes, Bip44Coins


ADDR_NUM: int = 5

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
# Print master key
print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive BIP44 coin keys: m/44'/60'
bip44_coin_ctx = bip44_mst_ctx.Purpose().Coin()

# Derive addresses: m/44'/60'/i'/0/0
print("Addresses:")
for i in range(ADDR_NUM):
    bip44_addr_ctx = bip44_coin_ctx.Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    print(f"  {i}. Address public key (bytes): {bip44_addr_ctx.PublicKey().RawCompressed().ToHex()}")
    print(f"  {i}. Address private key (bytes): {bip44_addr_ctx.PrivateKey().Raw().ToHex()}")
    print(f"  {i}. Address: {bip44_addr_ctx.PublicKey().ToAddress()}")
