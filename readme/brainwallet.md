## Brainwallet library

The brainwallet library allows to generate wallets where the private key is computed from a passphrase chosen by the user.\
Beside the fact that this method allows computing only one private key (hence only one address), _it's very insecure_ (humans are not a good source of entropy) and discouraged in favor of random HD wallets, but it could be useful to recover some very old wallets.

### Built-in algorithms

A brainwallet can be generated using a built-in algorithm. The supported algorithms are:

|Enumerative|Description|
|---|---|
|`BrainwalletAlgos.SHA256`|Private key is computed from user passphrase using SHA256|
|`BrainwalletAlgos.DOUBLE_SHA256`|Private key is computed from user passphrase using double SHA256|
|`BrainwalletAlgos.PBKDF2_HMAC_SHA512`|Private key is computed from user passphrase using PBKDF2 HMAC-SHA512|
|`BrainwalletAlgos.SCRYPT`|Private key is computed from user passphrase using Scrypt|

In case of `BrainwalletAlgos.PBKDF2_HMAC_SHA512`, these additional parameters can be optionally specified:

- `salt`: salt for PBKDF2 algorithm (default: empty string)
- `itr_num`: number of iteration for PBKDF2 algorithm (default: 2097152)

In case of `BrainwalletAlgos.SCRYPT`, these additional parameters can be optionally specified:

- `salt`: salt for Scrypt algorithm (default: empty string)
- `n`: CPU/Memory cost parameter for Scrypt algorithm (default: 131072)
- `r`: block size parameter for Scrypt algorithm (default: 8)
- `p`: parallelization parameter for Scrypt algorithm (default: 8)
:
### Coins

A brainwallet can be generated for all coins supported by `Bip44`.

The `BrainwalletCoins` enumerative, used to specify the coin, is just an alias for `Bip44Coins`.

### Generation using built-in algorithms

A wallet can be generated using a built-in algorithm with the `Generate` method, by specifying the algorithm and coin types.

**Code example**

    from bip_utils import Brainwallet, BrainwalletCoins, BrainwalletAlgos

    passphrase = "The quick brown fox jumps over the lazy dog"

    # Generate using SHA256 algorithm for Bitcoin
    brainwallet_btc = Brainwallet.Generate(
        passphrase,
        BrainwalletCoins.BITCOIN,
        BrainwalletAlgos.SHA256
    )

    # Generate using Scrypt algorithm for Ethereum with custom salt
    brainwallet_eth = Brainwallet.Generate(
        passphrase,
        BrainwalletCoins.ETHEREUM,
        BrainwalletAlgos.SCRYPT,
        salt="custom salt"
    )

### Generation using custom algorithms

A wallet can be generated using a custom algorithm with the `GenerateWithCustomAlgo` method, by specifying the algorithm class and coin type.\
In order to create a custom algorithm, a class inheriting the `IBrainwalletAlgo` interface and implementing the `ComputePrivateKey` method shall be defined.\
The output length of the `ComputePrivateKey` method shall be the length of the private key of the specific coin, usually 32-byte long.

**Code example**

    from typing import Any
    from bip_utils import Brainwallet, BrainwalletCoins, IBrainwalletAlgo, Sha512_256

    # Custom brainwallet algorithm using SHA512/256 for computing the private key
    class BrainwalletCustomAlgo(IBrainwalletAlgo):
        @staticmethod
        def ComputePrivateKey(passphrase: str,
                              **kwargs: Any) -> bytes:
            return Sha512_256.QuickDigest(passphrase)

    passphrase = "The quick brown fox jumps over the lazy dog"

    # Generate brainwallet for Litecoin with the custom algorithm
    brainwallet_ltc = Brainwallet.GenerateWithCustomAlgo(
        passphrase,
        BrainwalletCoins.LITECOIN,
        BrainwalletCustomAlgo
    )

## Getting keys

The `Brainwallet` class uses the computed private key to construct a `Bip44` object.\
Therefore, private and public keys can be use exactly like the `Bip44` class.

**Code example**

    from bip_utils import Brainwallet, BrainwalletCoins, BrainwalletAlgos

    passphrase = "The quick brown fox jumps over the lazy dog"

    brainwallet_btc = Brainwallet.Generate(
        passphrase,
        BrainwalletCoins.BITCOIN,
        BrainwalletAlgos.SHA256
    )

    print(brainwallet_btc.PrivateKey().Raw().ToHex())
    print(brainwallet_btc.PublicKey().ToExtended())
    print(brainwallet_btc.PublicKey().ToAddress())
