"""Example of keys derivation using BIP32 (ed25519 curve based on Khovratovich/Law paper)."""

from bip_utils import AlgoAddrEncoder, Bip32KholawEd25519, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed, using ed25519 curve for key derivation
bip32_mst_ctx = Bip32KholawEd25519.FromSeed(seed_bytes)
# Print master key
print(f"Master key (bytes): {bip32_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip32_mst_ctx.PrivateKey().ToExtended()}")

# Derive a path
bip32_der_ctx = bip32_mst_ctx.DerivePath("m/44'/283'/0'/0/0")
# Print key
print(f"Derived private key (bytes): {bip32_der_ctx.PrivateKey().Raw().ToHex()}")
print(f"Derived private key (extended): {bip32_der_ctx.PrivateKey().ToExtended()}")
print(f"Derived public key (bytes): {bip32_der_ctx.PublicKey().RawCompressed().ToHex()}")
print(f"Derived public key (extended): {bip32_der_ctx.PublicKey().ToExtended()}")

# Print address in Algorand encoding
# The BIP32 elliptic curve shall be the same one expected by Algorand (ed25519 in this case)
algo_addr = AlgoAddrEncoder.EncodeKey(bip32_der_ctx.PublicKey().KeyObject())
print(f"Address (ALGO): {algo_addr}")
