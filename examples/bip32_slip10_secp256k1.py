"""Example of keys derivation using BIP32 (secp256k1 curve)."""

from bip_utils import Bip32Slip10Secp256k1, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, EthAddrEncoder


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed, using secp256k1 curve for key derivation
bip32_mst_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
# Print master key
print(f"Master key (bytes): {bip32_mst_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master key (extended): {bip32_mst_ctx.PrivateKey().ToExtended()}")

# Derive a path
bip32_der_ctx = bip32_mst_ctx.DerivePath("m/44'/60'/0'/0/0")
# Print key
print(f"Derived private key (bytes): {bip32_der_ctx.PrivateKey().Raw().ToHex()}")
print(f"Derived private key (extended): {bip32_der_ctx.PrivateKey().ToExtended()}")
print(f"Derived public key (bytes): {bip32_der_ctx.PublicKey().RawCompressed().ToHex()}")
print(f"Derived public key (extended): {bip32_der_ctx.PublicKey().ToExtended()}")

# Print address in Ethereum encoding
# The BIP32 elliptic curve shall be the same one expected by Ethereum (secp256k1 in this case)
eth_addr = EthAddrEncoder.EncodeKey(bip32_der_ctx.PublicKey().KeyObject())
print(f"Address (ETH): {eth_addr}")
