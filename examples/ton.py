"""Example of mnemonic generation and key derivation for TON."""

from bip_utils import (
    Bip32Ed25519Slip,
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    Bip44,
    Bip44Coins,
    Bip44ConfGetter,
    TonAddrEncoder,
    TonAddrVersions,
    TonMnemonicGenerator,
    TonMnemonicValidator,
    TonSeedGenerator,
    TonSeedTypes,
    TonWordsNum,
    Ton,
)

#
# Generation like ton-crypto
#

# Generate random mnemonic
mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
print(f"Mnemonic: {mnemonic}")

# Validate mnemonic
is_valid = TonMnemonicValidator().IsValid(mnemonic)
print(f"Mnemonic valid: {is_valid}")

# Generate seed for HD keys
seed_bytes = TonSeedGenerator(mnemonic).Generate(seed_type=TonSeedTypes.HD_KEY)
print(f"Seed for HD keys: {seed_bytes.hex()}")

# Generate seed for keypair
seed_bytes = TonSeedGenerator(mnemonic).Generate(seed_type=TonSeedTypes.PRIVATE_KEY)
print(f"Seed for keypair: {seed_bytes.hex()}")

# Generate keypair and address
ton = Ton.FromSeed(seed_bytes)
print(f"Ton public key (ton-crypto): {ton.PublicKey().RawCompressed().ToHex()}")
print(f"Ton private key (ton-crypto): {ton.PrivateKey().Raw().ToHex()}")
print(f"Ton address (ton-crypto, V5R1): {ton.GetAddress(version=TonAddrVersions.V5R1)}")


#
# Generation like Tonkeeper, Tonwallet, Trustwallet
#

# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.TON)
bip44_def_ctx = bip44_mst_ctx.DeriveDefaultPath()

# Print keys
print(f"Ton private key: {bip44_def_ctx.PrivateKey().Raw().ToHex()}")
print(f"Ton public key: {bip44_def_ctx.PublicKey().RawCompressed().ToHex()[1:]}")
# Print address (default version is V4)
print(f"Ton address (V4): {bip44_def_ctx.PublicKey().ToAddress()}")
# Print address with other versions
pub_key_obj = bip44_def_ctx.PublicKey().Bip32Key().KeyObject()
print(f"Ton address (V3R1): {TonAddrEncoder.EncodeKey(pub_key_obj, version=TonAddrVersions.V3R1)}")
print(f"Ton address (V3R2): {TonAddrEncoder.EncodeKey(pub_key_obj, version=TonAddrVersions.V3R2)}")
print(f"Ton address (V5R1): {TonAddrEncoder.EncodeKey(pub_key_obj, version=TonAddrVersions.V5R1)}")

#
# Generation like Ledger
#

# Get coin index from configuration
coin_idx = Bip44ConfGetter.GetConfig(Bip44Coins.TON).CoinIndex()
# Derive
derivation_path = f"m/44'/{coin_idx}'/0'/0'/0'/0'"
bip32_ctx = Bip32Ed25519Slip.FromSeed(seed_bytes).DerivePath(derivation_path)

# Construct BIP44 object from private key
priv_key_bytes = bip32_ctx.PrivateKey().Raw().ToBytes()
bip44_ctx = Bip44.FromPrivateKey(priv_key_bytes, Bip44Coins.TON)
# Print address
print(f"Ton address (Ledger, V4): {bip44_ctx.PublicKey().ToAddress()}")
