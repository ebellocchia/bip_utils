"""Example of deterministic entropy derivation using BIP85."""

from bip_utils import Bip39Languages, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip85


# Generate random mnemonic (i.e. the only one to be backed up)
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(f"Master mnemonic: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Construct from seed (an extended master key or a Bip32Slip10Secp256k1 object can be used as well)
bip85 = Bip85.FromSeed(seed_bytes)
print(f"Master key: {bip85.Bip32Object().PrivateKey().ToExtended()}")

# Derive child mnemonics for other wallets (one for each index)
for i in range(3):
    print(f"Child mnemonic {i} (12 words): {bip85.Bip39(Bip39Languages.ENGLISH, Bip39WordsNum.WORDS_NUM_12, i)}")
print(f"Child mnemonic 0 (24 words, Italian): {bip85.Bip39(Bip39Languages.ITALIAN, Bip39WordsNum.WORDS_NUM_24, 0)}")

# Derive keys
print(f"HD-Seed WIF: {bip85.HdSeedWif(0)}")
print(f"Extended master key: {bip85.Xprv(0)}")
print(f"Nostr private key: {bip85.Nostr(1, 1)}")

# Derive entropy and passwords
print(f"Hex entropy (32 bytes): {bip85.Hex(32, 0)}")
print(f"Base64 password (20 characters): {bip85.PwdBase64(20, 0)}")
print(f"Base85 password (16 characters): {bip85.PwdBase85(16, 0)}")
# PIN with 6 digits (i.e. 6 rolls of a 10-sided dice)
print(f"PIN: {''.join(str(roll) for roll in bip85.Dice(10, 6, 0))}")
