"""Example of SPL token account address generation for Solana."""

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44, Bip44Coins, SplToken


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA).DeriveDefaultPath()
# Print default address
addr = bip44_ctx.PublicKey().ToAddress()
print(f"Default address: {addr}")

# Get address for USDC token
usdc_addr = SplToken.GetAssociatedTokenAddress(addr, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
print(f"USDC account address: {usdc_addr}")
# Get address for Serum token
srm_addr = SplToken.GetAssociatedTokenAddress(addr, "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt")
print(f"SRM account address: {srm_addr}")
