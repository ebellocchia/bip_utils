"""Example of mnemonic generation and key derivation like Electrum wallet."""

from bip_utils import (
    ElectrumV2WordsNum, ElectrumV2MnemonicTypes, ElectrumV2MnemonicGenerator, ElectrumV2SeedGenerator,
    Bip32Secp256k1, Bip44Coins, Bip84Coins, Bip44ConfGetter, Bip84ConfGetter, P2PKHAddr, P2WPKHAddr
)

# Generate random standard mnemonic
standard_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Standard mnemonic: {standard_mnemonic}")
# Generate seed from mnemonic
standard_seed_bytes = ElectrumV2SeedGenerator(standard_mnemonic).Generate()

# Construct from seed, using secp256k1 curve for key derivation
bip32_mst_ctx = Bip32Secp256k1.FromSeed(standard_seed_bytes)

# Derive the first 5 standard addresses
for i in range(5):
    bip32_addr_ctx = bip32_mst_ctx.DerivePath(f"m/0/{i}")
    segwit_address = P2PKHAddr.EncodeKey(
        bip32_addr_ctx.PublicKey().KeyObject(),
        **Bip44ConfGetter.GetConfig(Bip44Coins.BITCOIN).AddrParams()
    )
    print(f"{i}. Standard address: {segwit_address}")

print("")

# Generate random segwit mnemonic
segwit_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Segwit mnemonic: {segwit_mnemonic}")
# Generate seed from mnemonic
segwit_seed_bytes = ElectrumV2SeedGenerator(segwit_mnemonic).Generate()

# Construct from seed, using secp256k1 curve for key derivation
bip32_mst_ctx = Bip32Secp256k1.FromSeed(segwit_seed_bytes)

# Derive the first 5 segwit addresses
for i in range(5):
    bip32_addr_ctx = bip32_mst_ctx.DerivePath(f"m/0'/0/{i}")
    segwit_address = P2WPKHAddr.EncodeKey(
        bip32_addr_ctx.PublicKey().KeyObject(),
        **Bip84ConfGetter.GetConfig(Bip84Coins.BITCOIN).AddrParams()
    )
    print(f"{i}. Segwit address: {segwit_address}")
