"""Example of Nostr keys derivation (NIP-06 and BIP85) and encoding (NIP-19)."""

from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip85,
    NostrAddrDecoder,
    NostrAddrEncoder,
    NostrNsecDecoder,
    NostrNsecEncoder,
    Secp256k1PrivateKey,
)


# Generate random mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Derive keys as defined by NIP-06 (path m/44'/1237'/<account>'/0/0)
bip44_acc_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.NOSTR).Purpose().Coin()
for i in range(3):
    bip44_addr_ctx = bip44_acc_ctx.Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    print(f"NIP-06 account {i}:")
    # The address is the public key in npub format
    print(f"  Public key (npub): {bip44_addr_ctx.PublicKey().ToAddress()}")
    print(f"  Private key (nsec): {NostrNsecEncoder.Encode(bip44_addr_ctx.PrivateKey().Raw().ToBytes())}")

# Derive keys with the Nostr application of BIP85 (identity and account index start from 1)
bip85 = Bip85.FromSeed(seed_bytes)
nsec = bip85.Nostr(1, 1)
priv_key = Secp256k1PrivateKey.FromBytes(NostrNsecDecoder.Decode(nsec))
npub = NostrAddrEncoder.EncodeKey(priv_key.PublicKey())
print("BIP85 identity 1, account 1:")
print(f"  Public key (npub): {npub}")
print(f"  Public key (hex): {NostrAddrDecoder.DecodeAddr(npub).hex()}")
print(f"  Private key (nsec): {nsec}")
print(f"  Private key (hex): {priv_key.Raw().ToHex()}")
