## BIP-0044, BIP-0049, BIP-0084, BIP-0086 libraries

The BIP-0044, BIP-0049, BIP-0084 and BIP-0086 libraries allows deriving a hierarchy of keys as defined by:
- [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP-0049](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- [BIP-0084](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [BIP-0086](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)

They internally use the BIP-0032 classes for keys derivation, selecting the correct one depending on the elliptic curve of the specific coin.

### Coin types

#### BIP-0044

Supported coins enumerative for BIP-0044:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Akash Network|`Bip44Coins.AKASH_NETWORK`|-|
|Algorand|`Bip44Coins.ALGORAND`|-|
|Aptos|`Bip44Coins.APTOS`|-|
|Avalanche C-Chain|`Bip44Coins.AVAX_C_CHAIN`|-|
|Avalanche P-Chain|`Bip44Coins.AVAX_P_CHAIN`|-|
|Avalanche X-Chain|`Bip44Coins.AVAX_X_CHAIN`|-|
|Axelar|`Bip44Coins.AXELAR`|-|
|Band Protocol|`Bip44Coins.BAND_PROTOCOL`|-|
|Binance Chain|`Bip44Coins.BINANCE_CHAIN`|-|
|Binance Smart Chain|`Bip44Coins.BINANCE_SMART_CHAIN`|-|
|Bitcoin|`Bip44Coins.BITCOIN`|`Bip44Coins.BITCOIN_TESTNET`|
|Bitcoin Cash|`Bip44Coins.BITCOIN_CASH`|`Bip44Coins.BITCOIN_CASH_TESTNET`|
|[Bitcoin Cash SLP](https://reference.cash/protocol/slp)|`Bip44Coins.BITCOIN_CASH_SLP`|`Bip44Coins.BITCOIN_CASH_SLP_TESTNET`|
|BitcoinSV|`Bip44Coins.BITCOIN_SV`|`Bip44Coins.BITCOIN_SV_TESTNET`|
|Cardano Byron (Icarus)|`Bip44Coins.CARDANO_BYRON_ICARUS`, see [Cardano](https://github.com/ebellocchia/bip_utils/tree/master/readme/cardano.md)|-|
|Cardano Byron (Ledger)|`Bip44Coins.CARDANO_BYRON_LEDGER`, see [Cardano](https://github.com/ebellocchia/bip_utils/tree/master/readme/cardano.md)|-|
|Celo|`Bip44Coins.CELO`|-|
|Certik|`Bip44Coins.CERTIK`|-|
|Chihuahua|`Bip44Coins.CHIHUAHUA`|-|
|Cosmos|`Bip44Coins.COSMOS`|-|
|Dash|`Bip44Coins.DASH`|`Bip44Coins.DASH_TESTNET`|
|Dogecoin|`Bip44Coins.DOGECOIN`|`Bip44Coins.DOGECOIN_TESTNET`|
|eCash|`Bip44Coins.ECASH`|`Bip44Coins.ECASH_TESTNET`|
|Elrond|`Bip44Coins.ELROND`|-|
|EOS|`Bip44Coins.EOS`|-|
|Ergo|`Bip44Coins.ERGO`|`Bip44Coins.ERGO_TESTNET`|
|Ethereum|`Bip44Coins.ETHEREUM`|-|
|Ethereum Classic|`Bip44Coins.ETHEREUM_CLASSIC`|-|
|Fantom Opera|`Bip44Coins.FANTOM_OPERA`|-|
|Filecoin|`Bip44Coins.FILECOIN`|-|
|Harmony One (Cosmos address)|`Bip44Coins.HARMONY_ONE_ATOM`|-|
|Harmony One (Ethereum address)|`Bip44Coins.HARMONY_ONE_ETH`|-|
|Harmony One (Metamask address)|`Bip44Coins.HARMONY_ONE_METAMASK`|-|
|Huobi Chain|`Bip44Coins.HUOBI_CHAIN`|-|
|Icon|`Bip44Coins.ICON`|-|
|IRIS Network|`Bip44Coins.IRIS_NET`|-|
|Kava|`Bip44Coins.KAVA`|-|
|Kusama (ed25519 SLIP-0010)|`Bip44Coins.KUSAMA_ED25519_SLIP`|-|
|Litecoin|`Bip44Coins.LITECOIN`|`Bip44Coins.LITECOIN_TESTNET`|
|Monero (ed25519 SLIP-0010, please see the Monero paragraph below)|`Bip44Coins.MONERO_ED25519_SLIP`|-|
|Monero (secp256k1, please see the Monero paragraph below)|`Bip44Coins.MONERO_SECP256K1`|-|
|Nano|`Bip44Coins.NANO`|-|
|Near Protocol|`Bip44Coins.NEAR_PROTOCOL`|-|
|NEO|`Bip44Coins.NEO`|-|
|OKEx Chain (Cosmos address)|`Bip44Coins.OKEX_CHAIN_ATOM`|-|
|OKEx Chain (Ethereum address)|`Bip44Coins.OKEX_CHAIN_ETH`|-|
|OKEx Chain (Old Cosmos address before mainnet upgrade)|`Bip44Coins.OKEX_CHAIN_ATOM_OLD`|-|
|Ontology|`Bip44Coins.ONTOLOGY`|-|
|Osmosis|`Bip44Coins.OSMOSIS`|-|
|Pi Network|`Bip44Coins.PI_NETWORK`|-|
|Polkadot (ed25519 SLIP-0010)|`Bip44Coins.POLKADOT_ED25519_SLIP`|-|
|Polygon|`Bip44Coins.POLYGON`|-|
|Ripple|`Bip44Coins.RIPPLE`|-|
|Secret Network (old path)|`Bip44Coins.SECRET_NETWORK_OLD`|-|
|Secret Network (new path)|`Bip44Coins.SECRET_NETWORK_NEW`|-|
|Solana|`Bip44Coins.SOLANA`|-|
|Stellar|`Bip44Coins.STELLAR`|-|
|Terra|`Bip44Coins.TERRA`|-|
|Tezos|`Bip44Coins.TEZOS`|-|
|Theta Network|`Bip44Coins.THETA`|-|
|Tron|`Bip44Coins.TRON`|-|
|VeChain|`Bip44Coins.VECHAIN`|-|
|Verge|`Bip44Coins.VERGE`|-|
|Zcash|`Bip44Coins.ZCASH`|`Bip44Coins.ZCASH_TESTNET`|
|Zilliqa|`Bip44Coins.ZILLIQA`|-|

The code is structured so that it can be easily extended with other coins if needed (provided that the coin elliptic curve is supported).

**NOTES**

- `Bip44Coins.HARMONY_ONE_ETH` generates the address using the Harmony One coin index (i.e. *1023*).
This is the behavior of the official Harmony One wallet and the Ethereum address that you get in the Harmony One explorer.\
  However, if you just add the Harmony One network in Metamask, Metamask will use the Ethereum coin index (i.e. *60*) thus resulting in a different address.
Therefore, if you need to generate the Harmony One address for Metamask, use `Bip44Coins.HARMONY_ONE_METAMASK`.
- `Bip44Coins.OKEX_CHAIN_ETH` and `Bip44Coins.OKEX_CHAIN_ATOM` generate the address using the Ethereum coin index (i.e. *60*).
These formats are the ones used by the OKEx wallet. `Bip44Coins.OKEX_CHAIN_ETH` is compatible with Metamask.\
`Bip44Coins.OKEX_CHAIN_ATOM_OLD` generates the address using the OKEx Chain coin index (i.e. *996*).
  This address format was used before the mainnet upgrade (some wallets still use it, e.g. Cosmostation).

#### BIP-0049

Supported coins enumerative for BIP-0049:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin|`Bip49Coins.BITCOIN`|`Bip49Coins.BITCOIN_TESTNET`|
|Bitcoin Cash|`Bip49Coins.BITCOIN_CASH`|`Bip49Coins.BITCOIN_CASH_TESTNET`|
|[Bitcoin Cash SLP](https://reference.cash/protocol/slp)|`Bip49Coins.BITCOIN_CASH_SLP`|`Bip49Coins.BITCOIN_CASH_SLP_TESTNET`|
|BitcoinSV|`Bip49Coins.BITCOIN_SV`|`Bip49Coins.BITCOIN_SV_TESTNET`|
|Dash|`Bip49Coins.DASH`|`Bip49Coins.DASH_TESTNET`|
|Dogecoin|`Bip49Coins.DOGECOIN`|`Bip49Coins.DOGECOIN_TESTNET`|
|eCash|`Bip49Coins.ECASH`|`Bip49Coins.ECASH_TESTNET`|
|Litecoin|`Bip49Coins.LITECOIN`|`Bip49Coins.LITECOIN_TESTNET`|
|Zcash|`Bip49Coins.ZCASH`|`Bip49Coins.ZCASH_TESTNET`|

#### BIP-0084

Supported coins enumerative for BIP-0084:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin|`Bip84Coins.BITCOIN`|`Bip84Coins.BITCOIN_TESTNET`|
|Litecoin|`Bip84Coins.LITECOIN`|`Bip84Coins.LITECOIN_TESTNET`|

#### BIP-0086

Supported coins enumerative for BIP-0086:

|Coin|Main net enum|Test net enum|
|---|---|---|
|Bitcoin|`Bip86Coins.BITCOIN`|`Bip86Coins.BITCOIN_TESTNET`|

### Construction from seed

A Bip class can be constructed from a seed. The seed can be specified manually or generated by `Bip39SeedGenerator`.

**Code example**

    import binascii
    from bip_utils import Bip39SeedGenerator, Bip44Coins, Bip44

    # Generate from mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Specify seed manually
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Derivation path returned: m
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

### Construction from extended key

A Bip class can be constructed directly from an extended key.\
The returned Bip object will be at the same depth of the specified key. If the depth of the key is not valid, a `Bip44DepthError` exception will be raised.

**Code example**

    from bip_utils import Bip44Coins, Bip44

    # Private extended key
    key_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    # Construct from extended key
    bip44_mst_ctx = Bip44.FromExtendedKey(key_str, Bip44Coins.BITCOIN)

### Construction from private key

A Bip class can be constructed directly from a private key, with the possibility to specify the derivation data.\
Like [`Bip32`](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip32.md), if only the key bytes is specified, it will be considered a master key since there is no way to recover the key derivation data from the key bytes.\
Therefore, the returned object will have a depth and index equal to zero, a zero chain code and parent fingerprint.

**Code example**

    import binascii
    from bip_utils import Bip32KeyData, Bip44Coins, Bip44, Secp256k1PrivateKey
    
    # Construct from private key bytes
    priv_key_bytes = binascii.unhexlify(b"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    bip44_mst_ctx = Bip44.FromPrivateKey(priv_key_bytes, Bip44Coins.BITCOIN)
    # Or key object directly (the key type shall match the curve used by the coin, otherwise Bip32KeyError will be raised)
    bip44_mst_ctx = Bip44.FromPrivateKey(Secp256k1PrivateKey.FromBytes(priv_key_bytes), Bip44Coins.BITCOIN)
    
    # Construct by specifying derivation data
    chain_code_bytes = binascii.unhexlify(b"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    bip44_mst_ctx = Bip44.FromPrivateKey(
        priv_key_bytes,
        Bip44Coins.BITCOIN,
        Bip32KeyData(
            chain_code=chain_code_bytes,
            depth=1,
            index=2,
            parent_fprint=binascii.unhexlify(b"3442193e")
        )
    )

### Construction from public key

A Bip class can be constructed directly from a public key, with the possibility to specify the derivation data.\
If only the key bytes is specified, it will be considered an account key (first level where not-hardened derivation is supported) since there is no way to recover the key derivation data from the key bytes.\
Therefore, the returned object will have a depth and index equal to zero, a zero chain code and parent fingerprint.

**Code example**

    import binascii
    from bip_utils import Bip32KeyData, Bip44Coins, Bip44, Secp256k1PublicKey
    
    # Construct from public key bytes
    pub_key_bytes = binascii.unhexlify(b"02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")
    bip44_mst_ctx = Bip44.FromPublicKey(pub_key_bytes, Bip44Coins.BITCOIN)
    # Or key object directly (the key type shall match the curve used by the coin, otherwise Bip32KeyError will be raised)
    bip44_mst_ctx = Bip44.FromPublicKey(Secp256k1PublicKey.FromBytes(pub_key_bytes), Bip44Coins.BITCOIN)
    
    # Construct by specifying derivation data
    chain_code_bytes = binascii.unhexlify(b"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    bip44_mst_ctx = Bip44.FromPublicKey(
        pub_key_bytes,
        Bip44Coins.BITCOIN,
        Bip32KeyData(
            chain_code=chain_code_bytes,
            depth=4,
            index=1,
            parent_fprint=binascii.unhexlify(b"3442193e")
        )
    )

### Keys derivation

Like [`Bip32`](https://github.com/ebellocchia/bip_utils/tree/master/readme/bip32.md), each time a key is derived a new instance of the Bip class is returned.\
The keys must be derived with the levels specified by BIP-0044:

    m / purpose' / coin_type' / account' / change / address_index

using the correspondent methods. If keys are derived in the wrong level, a `Bip44DepthError` will be raised.\
The private and public extended keys can be printed at any level.

**NOTE**: In case not-hardened private derivation is not supported (e.g. in ed25519 SLIP-0010), all indexes will be hardened:

    m / purpose' / coin_type' / account' / change' / address_index'

**Code example**

    import binascii
    from bip_utils import Bip44Changes, Bip44Coins, Bip44Levels, Bip44
    
    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    # Create from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    
    # Print master key in extended format
    print(bip44_mst_ctx.PrivateKey().ToExtended())
    # Print master key in hex format
    print(bip44_mst_ctx.PrivateKey().Raw().ToHex())
    # Print the master key in WIF
    print(bip44_mst_ctx.PrivateKey().ToWif())
    
    # Print public key in extended format
    print(bip44_mst_ctx.PublicKey().ToExtended())
    # Print public key in raw uncompressed format
    print(bip44_mst_ctx.PublicKey().RawUncompressed().ToHex())
    # Print public key in raw compressed format
    print(bip44_mst_ctx.PublicKey().RawCompressed().ToHex())
    
    # Print level
    print(bip44_mst_ctx.Level())
    # Check level
    print(bip44_mst_ctx.IsLevel(Bip44Levels.MASTER))
    
    # Derive account 0 for Bitcoin: m/44'/0'/0'
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    # Print keys in extended format
    print(bip44_acc_ctx.PrivateKey().ToExtended())
    print(bip44_acc_ctx.PublicKey().ToExtended())
    # Address of account level
    print(bip44_acc_ctx.PublicKey().ToAddress())
    
    # Derive the external chain: m/44'/0'/0'/0
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    # Print again keys in extended format
    print(bip44_chg_ctx.PrivateKey().ToExtended())
    print(bip44_chg_ctx.PublicKey().ToExtended())
    # Address of change level
    print(bip44_chg_ctx.PublicKey().ToAddress())
    
    # Derive the first 20 addresses of the external chain: m/44'/0'/0'/0/i
    for i in range(20):
        bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    
        # Print extended keys and address
        print(bip44_addr_ctx.PrivateKey().ToExtended())
        print(bip44_addr_ctx.PublicKey().ToExtended())
        print(bip44_addr_ctx.PublicKey().ToAddress())

**NOTE:** since all the classes derive from the same base class, their usage is the same. Therefore, in all the code examples `Bip44` can be substituted by `Bip49`, `Bip84` or `Bip86` without changing the code.

### Default derivation paths

Most of the coins (especially the ones using the secp256k1 curve) use the complete BIP-0044 path to derive the address private key:

    m / purpose' / coin_type' / account' / change / address_index

However, this doesn't apply all coins. For example, Solana uses the following path to derive the address private key: m/44'/501'/0'\
This can be derived manually, for example:

    import binascii
    from bip_utils import Bip44Coins, Bip44

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Derive m/44'/501'/0'
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    # Default address generated by the wallet (e.g. TrustWallet): m/44'/501'/0'
    print(bip44_acc_ctx.PublicKey().ToAddress())

However, in order to avoid remembering the default path for each coin, the `DeriveDefaultPath` method can be used to automatically derive the default path:

    import binascii
    from bip_utils import Bip44Coins, Bip44

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Automatically derive m/44'/501'/0'
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA).DeriveDefaultPath()
    # Same as before
    print(bip44_def_ctx.PublicKey().ToAddress())

    # Automatically derive m/44'/3'/0'/0/0
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.DOGECOIN).DeriveDefaultPath()
    # Same as before
    print(bip44_def_ctx.PublicKey().ToAddress())

### Polkadot/Kusama addresses generation

Polkadot and Kusama don't support BIP44, so if you use them through the `Bip44` class you're basically "forcing" them to follow it. Therefore, keys and addresses generated in this way will be different from the official Polkadot wallet.\
For this, I used the same implementation of TrustWallet, i.e.:
- The derivation scheme is based on ed25519 SLIP-0010
- The default derivation path is: m/44'/354'/0'/0'/0'

If you want to get the same keys and addresses of the Polkadot-JS wallet, use the `Substrate` module (see the [related paragraph](https://github.com/ebellocchia/bip_utils/tree/master/readme/substrate.md)).

### Monero addresses generation

Monero works differently from other coins, because it has 2 private keys and 2 public keys (one for spending, one for viewing).\
Moreover, it has its own algorithm to generate the so-called "subaddresses", which have nothing to do with the addresses derived at the "address" level in BIP44.\
Therefore, Monero shall be treated separately to get keys and addresses by using the `Monero` module.

Like Polkadot/Kusama in the previous paragraph, Monero doesn't support BIP44 so if you use it through the `Bip44` class you're basically "forcing" Monero to follow it.\
Since there is no specification that states how to implement Monero using BIP44, I look a little bit around and I created two implementations:
- `Bip44Coins.MONERO_ED25519_SLIP` uses the ed25519 curve (like Monero itself) with the SLIP-0010 derivation scheme and the default derivation path is m/44'/128'/0'/0'/0'
- `Bip44Coins.MONERO_SECP256K1` uses the secp256k1 curve (like Bitcoin) and the default derivation path is m/44'/128'/0'/0/0 (like the Ledger implementation)

Of course, you are free to derive other paths if you want.\
Whatever implementation or path you choose, the Monero private spend key is computed from the `Bip44` private key as follows:
- perform keccak256 of the key bytes
- apply `sc_reduce` to the result to get a valid Monero private key

**Code example**

    import binascii
    from bip_utils import Bip44Coins, Bip44, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Create BIP44 object and derive default path
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP).DeriveDefaultPath()

    # Create Monero object from the BIP44 private key -> monero_priv_spend_key = sc_reduce(kekkak256(bip44_priv_key))
    monero = Monero.FromBip44PrivateKey(bip44_def_ctx.PrivateKey().Raw().ToBytes())

    # Print keys
    print(monero.PrivateSpendKey().Raw().ToHex())
    print(monero.PrivateViewKey().Raw().ToHex())
    print(monero.PublicSpendKey().RawCompressed().ToHex())
    print(monero.PublicViewKey().RawCompressed().ToHex())

    # Print primary address
    print(monero.PrimaryAddress())
    # Print subaddresses
    print(monero.Subaddress(0))         # Account 0 (default), Subaddress 0 (same as primary address)
    print(monero.Subaddress(1))         # Account 0 (default), Subaddress 1
    print(monero.Subaddress(0, 1))      # Account 1, Subaddress 0
    print(monero.Subaddress(1, 1))      # Account 1, Subaddress 1

If you prefer not to perform the kekkak256 of the key bytes, you can just use the `Bip44` private key directly as a Monero seed:

**Code example**

    import binascii
    from bip_utils import Bip44Coins, Bip44, Monero

    # Seed bytes
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    # Create BIP44 object and derive default path
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.MONERO_ED25519_SLIP).DeriveDefaultPath()

    # Create Monero object using the BIP44 private key as seed -> monero_priv_spend_key = sc_reduce(bip44_priv_key)
    monero = Monero.FromSeed(bip44_def_ctx.PrivateKey().Raw().ToBytes())
    # Same as before...

Please note that, if the seed is generated from a Monero mnemonic phrase, you'll get the same keys and addresses of the official Monero wallets.\
For the usage of the `Monero` module alone, see the [related paragraph](https://github.com/ebellocchia/bip_utils/tree/master/readme/monero.md).
