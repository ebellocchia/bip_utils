"""Example of wallet creation using Algorand (same addresses of official wallet)."""

from bip_utils import AlgorandMnemonicGenerator, AlgorandSeedGenerator, AlgorandWordsNum, Bip44, Bip44Coins


# Generate random mnemonic
mnemonic = AlgorandMnemonicGenerator().FromWordsNumber(AlgorandWordsNum.WORDS_NUM_25)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = AlgorandSeedGenerator(mnemonic).Generate()

# The seed is used as private key in the official wallet
bip44_ctx = Bip44.FromPrivateKey(seed_bytes, Bip44Coins.ALGORAND)

# Print keys
print(f"Algorand private key: {bip44_ctx.PrivateKey().Raw().ToHex()}")
print(f"Algorand public key: {bip44_ctx.PublicKey().RawCompressed().ToHex()}")
# Print address
print(f"Algorand address: {bip44_ctx.PublicKey().ToAddress()}")
