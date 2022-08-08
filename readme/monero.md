## Monero library

The Monero library allows to generate Monero keys, primary address and subaddresses like the official Monero wallets.

### Coin types

Supported coins enumerative:

|Coin|Enum|
|---|---|
|Monero main net|`MoneroCoins.MONERO_MAINNET`|
|Monero stage net|`MoneroCoins.MONERO_STAGENET`|
|Monero test net|`MoneroCoins.MONERO_TESTNET`|

Coin type is passed to all construction methods. The default type is always Monero main net.

### Construction from seed

The class can be constructed from a seed, which is usually computed from the Monero mnemonic phrase.\
In case of a 24/25 words phrase, the seed corresponds to the private spend key. Otherwise, the private spend key will be the kekkak256 of the seed.

**NOTE:** Monero mnemonic phrase generation is currently not supported

**Code example**

    import binascii
    from bip_utils import MoneroCoins, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"851466f170f7d1dd88325d9f6b89328166fa23e3af712e74aa27cb16837ac10d")
    # Create from seed (default: Monero main net)
    monero = Monero.FromSeed(seed_bytes)
    # Return false
    print(monero.IsWatchOnly())

    # Create from seed for Monero stage net
    monero = Monero.FromSeed(seed_bytes, MoneroCoins.MONERO_STAGENET)
    # Create from seed for Monero test net
    monero = Monero.FromSeed(seed_bytes, MoneroCoins.MONERO_TESTNET)

### Construction from private spend key

The class can be constructed directly from the private spend key.

**Code example**

    import binascii
    from bip_utils import MoneroCoins, Monero, Ed25519MoneroPrivateKey

    # Create from private spend key bytes (default: Monero main net)
    key_bytes = binascii.unhexlify(b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107")
    monero = Monero.FromPrivateSpendKey(key_bytes)
    # Or key object directly
    monero = Monero.FromPrivateSpendKey(Ed25519MoneroPrivateKey.FromBytes(key_bytes))
    # Return false
    print(monero.IsWatchOnly())

    # Create from private spend key bytes for Monero test net
    key_bytes = binascii.unhexlify(b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107")
    monero = Monero.FromPrivateSpendKey(key_bytes, MoneroCoins.MONERO_TESTNET)

### Construction from Bip44 private key

The class can be constructed from a `Bip44` private key. Please refer to the related paragraph in the Bip44 chapter.

### Watch-only class

A watch-only class can be constructed from the private view key and the public spend key.

**Code example**

    import binascii
    from bip_utils import MoneroKeyError, MoneroCoins, Monero, Ed25519MoneroPrivateKey, Ed25519MoneroPublicKey

    # Keys
    priv_vkey_bytes = binascii.unhexlify(b"14467d1b9bb8d1fcfb5b7ae08cc9994367e917efd7e08cf94f9882ffa0629e09")
    pub_skey_bytes = binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422")

    # Create from watch-only keys (default: Monero main net)
    monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes)
    # Or key object directly
    monero = Monero.FromWatchOnly(Ed25519MoneroPrivateKey.FromBytes(priv_vkey_bytes),
                                  Ed25519MoneroPublicKey.FromBytes(pub_skey_bytes))
    # Return true
    print(monero.IsWatchOnly())
    # Getting the private spend key will raise a MoneroKeyError
    try:
        print(monero.PrivateSpendKey().Raw().ToHex())
    except MoneroKeyError as ex:
        print(ex)


    # Create from watch-only keys for Monero test net
    monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes, MoneroCoins.MONERO_TESTNET)

### Example of usage

**Code example**

    import binascii
    from bip_utils import Monero

    # Create from seed bytes
    seed_bytes = binascii.unhexlify(b"851466f170f7d1dd88325d9f6b89328166fa23e3af712e74aa27cb16837ac10d")
    monero = Monero.FromSeed(seed_bytes)
    # Print if watch-only
    print(monero.IsWatchOnly())

    # Print keys
    print(monero.PrivateSpendKey().Raw().ToHex())
    print(monero.PrivateSpendKey().Raw().ToBytes())
    print(monero.PrivateViewKey().Raw().ToHex())
    print(monero.PrivateViewKey().Raw().ToBytes())
    print(monero.PublicSpendKey().RawCompressed().ToHex())
    print(monero.PublicSpendKey().RawCompressed().ToBytes())
    print(monero.PublicViewKey().RawCompressed().ToHex())
    print(monero.PublicViewKey().RawCompressed().ToBytes())

    # Print primary address
    print(monero.PrimaryAddress())
    # Print integrated address
    payment_id = binascii.unhexlify(b"ccc172c2ffcac9d8")
    print(monero.IntegratedAddress(payment_id))
    # Print subaddresses
    print(monero.Subaddress(0))         # Account 0 (default), Subaddress 0 (same as primary address)
    print(monero.Subaddress(1))         # Account 0 (default), Subaddress 1
    print(monero.Subaddress(0, 1))      # Account 1, Subaddress 0
    print(monero.Subaddress(1, 1))      # Account 1, Subaddress 1
