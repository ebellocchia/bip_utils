from typing import Any

from bip_utils import Brainwallet, BrainwalletCoins, IBrainwalletAlgo, Sha512_256


# Custom brainwallet algorithm using SHA512/256 for computing the private key
class BrainwalletCustomAlgo(IBrainwalletAlgo):
    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        return Sha512_256.QuickDigest(passphrase)


# Passphrase chosen by user
passphrase = "The quick brown fox jumps over the lazy dog"

# Generate brainwallet with the custom algorithm
brainwallet = Brainwallet.GenerateWithCustomAlgo(
    passphrase,
    BrainwalletCoins.BITCOIN,
    BrainwalletCustomAlgo
)

print(f"Private key: {brainwallet.PrivateKey().Raw().ToHex()}")
print(f"Public key: {brainwallet.PublicKey().RawCompressed().ToHex()}")
print(f"Address: {brainwallet.PublicKey().ToAddress()}")
