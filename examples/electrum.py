"""Example of mnemonic generation and keys derivation like the Electrum wallet."""

import binascii

from bip_utils import (
    CoinsConf, ElectrumV1, ElectrumV1MnemonicGenerator, ElectrumV1SeedGenerator, ElectrumV1WordsNum,
    ElectrumV2MnemonicGenerator, ElectrumV2MnemonicTypes, ElectrumV2SeedGenerator, ElectrumV2Segwit, ElectrumV2Standard,
    ElectrumV2WordsNum, IPrivateKey, WifEncoder, WifPubKeyModes
)


ADDR_NUM: int = 5


# Encode private key to WIF
def priv_to_wif(priv_key: IPrivateKey,
                pub_key_mode: WifPubKeyModes = WifPubKeyModes.COMPRESSED) -> str:
    return WifEncoder.Encode(priv_key,
                             CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"),
                             pub_key_mode)


print("V1 Wallet")
# Generate random mnemonic
v1_mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(ElectrumV1WordsNum.WORDS_NUM_12)
print(f"Mnemonic: {v1_mnemonic}")
v1_seed_bytes = ElectrumV1SeedGenerator(v1_mnemonic).Generate()
print(f"Seed: {binascii.hexlify(v1_seed_bytes)}")
# Construct from seed
electrum_v1 = ElectrumV1.FromSeed(v1_seed_bytes)
# Print master key
print(f"Master private key: {priv_to_wif(electrum_v1.MasterPrivateKey(), WifPubKeyModes.UNCOMPRESSED)}")
# Derive V1 addresses: m/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    print(f"  {i}. Private key: {priv_to_wif(electrum_v1.GetPrivateKey(0, i), WifPubKeyModes.UNCOMPRESSED)}")
    print(f"  {i}. Address: {electrum_v1.GetAddress(0, i)}")

print("")
print("V2 Wallet (standard)")
# Generate random standard mnemonic
v2_standard_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Mnemonic: {v2_standard_mnemonic}")
# Generate seed from mnemonic
v2_standard_seed_bytes = ElectrumV2SeedGenerator(v2_standard_mnemonic).Generate()
print(f"Seed: {binascii.hexlify(v2_standard_seed_bytes)}")
# Construct from seed
electrum_v2_standard = ElectrumV2Standard.FromSeed(v2_standard_seed_bytes)
# Print master key
print(f"Master private key: {priv_to_wif(electrum_v2_standard.MasterPrivateKey().KeyObject())}")
# Derive standard addresses: m/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    print(f"  {i}. Private key: {priv_to_wif(electrum_v2_standard.GetPrivateKey(0, i).KeyObject())}")
    print(f"  {i}. Address: {electrum_v2_standard.GetAddress(0, i)}")

print("")
print("V2 Wallet (segwit)")
# Generate random segwit mnemonic
v2_segwit_mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT).FromWordsNumber(ElectrumV2WordsNum.WORDS_NUM_12)
print(f"Mnemonic: {v2_segwit_mnemonic}")
# Generate seed from mnemonic
v2_segwit_seed_bytes = ElectrumV2SeedGenerator(v2_segwit_mnemonic).Generate()
print(f"Seed: {binascii.hexlify(v2_segwit_seed_bytes)}")
# Construct from seed
electrum_v2_segwit = ElectrumV2Segwit.FromSeed(v2_segwit_seed_bytes)
# Print master key
print(f"Master private key: {priv_to_wif(electrum_v2_segwit.MasterPrivateKey().KeyObject())}")
# Derive segwit addresses: m/0'/0/i
print("Addresses:")
for i in range(ADDR_NUM):
    print(f"  {i}. Private key: {priv_to_wif(electrum_v2_segwit.GetPrivateKey(0, i).KeyObject())}")
    print(f"  {i}. Address: {electrum_v2_segwit.GetAddress(0, i)}")
