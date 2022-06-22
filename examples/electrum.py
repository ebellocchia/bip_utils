"""Example of mnemonic generation and key derivation like Electrum wallet."""

from bip_utils import (
    ElectrumV2WordsNum, ElectrumV2MnemonicTypes, ElectrumV2MnemonicGenerator, ElectrumV2SeedGenerator,
    Bip32Secp256k1, ElectrumV2WalletStandard, ElectrumV2WalletSegwit
)

# Generate random standard mnemonic
standard_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Standard mnemonic: {standard_mnemonic}")
# Generate seed from mnemonic
standard_seed_bytes = ElectrumV2SeedGenerator(standard_mnemonic).Generate()

# Construct from seed
electrum_standard = ElectrumV2WalletStandard(
    Bip32Secp256k1.FromSeed(standard_seed_bytes)
)
# Derive the first 5 standard addresses
for i in range(5):
    print(f"{i}. Standard address: {electrum_standard.GetAddress(0, i)}")

print("")

# Generate random segwit mnemonic
segwit_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Segwit mnemonic: {segwit_mnemonic}")
# Generate seed from mnemonic
segwit_seed_bytes = ElectrumV2SeedGenerator(segwit_mnemonic).Generate()

# Construct from seed
electrum_segwit = ElectrumV2WalletSegwit(
    Bip32Secp256k1.FromSeed(segwit_seed_bytes)
)
# Derive the first 5 segwit addresses
for i in range(5):
    print(f"{i}. Segwit address: {electrum_segwit.GetAddress(0, i)}")
