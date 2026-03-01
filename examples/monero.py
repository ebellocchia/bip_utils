"""Example of keys derivation for Monero (same addresses of official wallet)."""

from bip_utils import (
    BytesUtils,
    Monero,
    MoneroMnemonicGenerator,
    MoneroPolyseedMnemonicDecoder,
    MoneroPolyseedMnemonicEncoder,
    MoneroPolyseedMnemonicEncrypter,
    MoneroPolyseedMnemonicGenerator,
    MoneroPolyseedSeedGenerator,
    MoneroSeedGenerator,
    MoneroWordsNum,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import MoneroPolyseedLanguages


#
# Legacy Monero mnemonic (25 words)
#

print("--- Legacy Monero mnemonic ---")

# Generate random mnemonic
mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
print(f"Mnemonic string: {mnemonic}")
# Generate seed from mnemonic
seed_bytes = MoneroSeedGenerator(mnemonic).Generate()
print(f"Seed: {seed_bytes.hex()}")

# Construct from seed
monero = Monero.FromSeed(seed_bytes)

# Print keys
print(f"Monero private spend key: {monero.PrivateSpendKey().Raw().ToHex()}")
print(f"Monero private view key: {monero.PrivateViewKey().Raw().ToHex()}")
print(f"Monero public spend key: {monero.PublicSpendKey().RawCompressed().ToHex()}")
print(f"Monero public view key: {monero.PublicViewKey().RawCompressed().ToHex()}")

# Print primary address
print(f"Monero primary address: {monero.PrimaryAddress()}")
# Print integrated address
payment_id = BytesUtils.FromHexString("d6f093554c0daa94")
print(f"Monero integrated address: {monero.IntegratedAddress(payment_id)}")
# Print the first 5 subaddresses for account 0 and 1
for acc_idx in range(2):
    for subaddr_idx in range(5):
        print(f"Subaddress (account: {acc_idx}, index: {subaddr_idx}): {monero.Subaddress(subaddr_idx, acc_idx)}")

#
# Polyseed mnemonic (16 words), e.g. Cake Wallet
#

print("\n--- Polyseed mnemonic ---")

# Generate random Polyseed mnemonic (birthday defaults to current time)
mnemonic = MoneroPolyseedMnemonicGenerator(MoneroPolyseedLanguages.ENGLISH).FromRandom()
print(f"Mnemonic string: {mnemonic}")

# Decode to inspect data
data = MoneroPolyseedMnemonicDecoder().DecodeWithData(mnemonic)
print(f"Secret: {data.secret.hex()}")
print(f"Birthday timestamp: {data.birthday_timestamp}")
print(f"Is encrypted: {data.is_encrypted}")
print(f"User features: {data.user_features}")

# Generate 32-byte seed via PBKDF2-HMAC-SHA256
seed_bytes = MoneroPolyseedSeedGenerator(mnemonic).Generate()
print(f"Seed: {seed_bytes.hex()}")

# Construct from seed
monero = Monero.FromSeed(seed_bytes)

# Print keys
print(f"Monero private spend key: {monero.PrivateSpendKey().Raw().ToHex()}")
print(f"Monero private view key: {monero.PrivateViewKey().Raw().ToHex()}")
print(f"Monero public spend key: {monero.PublicSpendKey().RawCompressed().ToHex()}")
print(f"Monero public view key: {monero.PublicViewKey().RawCompressed().ToHex()}")

# Print the first 5 subaddresses for account 0 and 1
for acc_idx in range(1):
    for subaddr_idx in range(5):
        print(f"Subaddress (account: {acc_idx}, index: {subaddr_idx}): {monero.Subaddress(subaddr_idx, acc_idx)}")

# Encrypt the mnemonic with a password
encrypted_data = MoneroPolyseedMnemonicEncrypter.Crypt(data, "my_password")
encrypted_mnemonic = MoneroPolyseedMnemonicEncoder().EncodeData(encrypted_data)
print(f"Encrypted mnemonic: {encrypted_mnemonic}")

# Decrypt: decode the encrypted mnemonic, then decrypt
enc_data = MoneroPolyseedMnemonicDecoder().DecodeWithData(encrypted_mnemonic)
decrypted_data = MoneroPolyseedMnemonicEncrypter.Crypt(enc_data, "my_password")
decrypted_mnemonic = MoneroPolyseedMnemonicEncoder().EncodeData(decrypted_data)
print(f"Decrypted mnemonic: {decrypted_mnemonic}")
