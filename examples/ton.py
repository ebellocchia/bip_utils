from bip_utils import TonSeedGenerator, TonMnemonicGenerator, TonMnemonicValidator, Ton

# Generate mnemonic for Ton wallets such as Tonkeeper

mnemonic = TonMnemonicGenerator().FromWordsNumber(24)
print(f"Mnemonic: {mnemonic}")

# Validate mnemonic
is_valid = TonMnemonicValidator().IsValid(mnemonic)
print(f"Is the mnemonic valid? {is_valid}")

# Generate seed and address from memonic

seed = TonSeedGenerator(mnemonic).Generate()

# Default address type is v5r1
addr = Ton().FromSeed(seed).GetAddress()
print(f"V5R1 Address: {addr}")

# Generate v4 address
addr_v4 = Ton().FromSeed(seed).GetAddress("v4")
print(f"V4 Address: {addr_v4}")


# Generate addresses based on bip44 such as Trustwallet or Ledger

from bip_utils import Bip32Ed25519Slip, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44ConfGetter


# Mnemonic
mnemonic = "bachelor neither fall observe flee give sniff rebel access maximum property beach"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

coin_type = Bip44Coins.TON

# Get address using the Trustwallet derivation path
bip44_mst= Bip44.FromSeed(seed_bytes, coin_type)
bip44_acc= bip44_mst.Purpose().Coin().Account(0)
addr = bip44_acc.PublicKey().ToAddress()
print(f"Address using Trustwallet derivation path: {addr}")

# Ledger uses a non-standard derivation path, so we need to use Bip32 directly

# Get coin index from configuration
coin_idx = Bip44ConfGetter.GetConfig(coin_type).CoinIndex()
# Account index
account_idx = 0
derivation_path  = f"m/44'/{coin_idx}'/0'/0'/{account_idx}'/0'"

bip32_ctx = Bip32Ed25519Slip.FromSeed(seed_bytes).DerivePath(derivation_path)
priv_key_bytes = bip32_ctx.PrivateKey().Raw().ToBytes()


bip44_ctx = Bip44.FromPrivateKey(priv_key_bytes, coin_type)

addr = bip44_ctx.PublicKey().ToAddress()

print(f"Address using Ledger derivation path: {addr}")
