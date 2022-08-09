"""Example of keys derivation for Substrate (same addresses of PolkadotJS)."""

from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum, Substrate, SubstrateBip39SeedGenerator, SubstrateCoins


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = SubstrateBip39SeedGenerator(mnemonic).Generate()

# Construct from seed
substrate_ctx = Substrate.FromSeed(seed_bytes, SubstrateCoins.POLKADOT)
# Print master keys and address
print(f"Master private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {substrate_ctx.PublicKey().ToAddress()}")

# Derive a child key
substrate_ctx = substrate_ctx.ChildKey("//hard")
# Print derived keys and address
print(f"Derived private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
print(f"Derived public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
print(f"Derived address: {substrate_ctx.PublicKey().ToAddress()}")
# Print path
print(f"Path: {substrate_ctx.Path().ToStr()}")

# Derive a path
substrate_ctx = substrate_ctx.DerivePath("//0/1")
# Print derived keys and address
print(f"Derived private key (bytes): {substrate_ctx.PrivateKey().Raw().ToHex()}")
print(f"Derived public  key (bytes): {substrate_ctx.PublicKey().RawCompressed().ToHex()}")
print(f"Derived address: {substrate_ctx.PublicKey().ToAddress()}")
# Print path
print(f"Path: {substrate_ctx.Path().ToStr()}")
