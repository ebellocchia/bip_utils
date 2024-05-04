"""
Example of wallet creation using Neo N3 (same address of NeoLite).
NeoLite neither generate a mnemonic phrase nor derive keys.
It generates directly a private key and shows it in WIF format. This key is used it as wallet master key.
"""

from bip_utils import Bip44, Bip44Coins, CoinsConf, WifDecoder


PRIV_KEY_WIF: str = "L3tgppXLgdaeqSGSFw1Go3skBiy8vQAM7YMXvTHsKQtE16PBncSU"

# Decode private key
priv_key_bytes, _ = WifDecoder.Decode(PRIV_KEY_WIF, CoinsConf.NeoN3.ParamByKey("wif_net_ver"))
# Use the private key as a master key (no derivation)
bip44_ctx = Bip44.FromPrivateKey(priv_key_bytes, Bip44Coins.NEO_N3)

# Print keys
print(f"Neo N3 private key: {bip44_ctx.PrivateKey().Raw().ToHex()}")
print(f"Neo N3 public key: {bip44_ctx.PublicKey().RawCompressed().ToHex()}")
# Print address
print(f"Neo N3 address: {bip44_ctx.PublicKey().ToAddress()}")
