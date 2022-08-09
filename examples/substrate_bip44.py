"""Example of keys derivation for Substrate based on BIP44."""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Coins


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.POLKADOT_ED25519_SLIP)
# Print master key
print(f"Master key (bytes): {bip44_mst_ctx.PrivateKey().Raw().ToHex()}")

# Derive default path
bip_obj_def = bip44_mst_ctx.DeriveDefaultPath()
# Print default keys and address
print(f"Default public key (hex): {bip_obj_def.PublicKey().RawCompressed().ToHex()}")
print(f"Default private key (hex): {bip_obj_def.PrivateKey().Raw().ToHex()}")
print(f"Default address: {bip_obj_def.PublicKey().ToAddress()}")
