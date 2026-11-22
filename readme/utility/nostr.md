## Nostr

The Nostr library allows encoding/decoding secp256k1 private keys in *nsec* format, as defined by [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md).\
Public keys are encoded/decoded in *npub* format by the `NostrAddrEncoder`/`NostrAddrDecoder` classes (see [address encoding/decoding](https://github.com/ebellocchia/bip_utils/tree/master/readme/utility/addr.md)).\
`ValueError` is raised in case of errors, `Bech32ChecksumError` if the checksum of a *nsec* string is not valid.

**Code example**

    import binascii
    from bip_utils import NostrAddrDecoder, NostrAddrEncoder, NostrNsecDecoder, NostrNsecEncoder, Secp256k1PrivateKey

    # Private key bytes or a private key object can be used
    priv_key = binascii.unhexlify(b"67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")
    priv_key = Secp256k1PrivateKey.FromBytes(
        binascii.unhexlify(b"67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"))

    # Encode/Decode private key (nsec)
    nsec = NostrNsecEncoder.Encode(priv_key)
    priv_key_bytes = NostrNsecDecoder.Decode(nsec)

    # Encode/Decode public key (npub), the decoded bytes are the X coordinate
    npub = NostrAddrEncoder.EncodeKey(priv_key.PublicKey())
    pub_key_bytes = NostrAddrDecoder.DecodeAddr(npub)

**Code example (keys derivation as defined by NIP-06)**

    from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins, NostrNsecEncoder

    seed_bytes = Bip39SeedGenerator("leader monkey parrot ring guide accident before fence cannon height naive bean").Generate()

    # NIP-06 path is m/44'/1237'/<account>'/0/0, so only the account index shall be changed
    bip44_addr_ctx = (Bip44.FromSeed(seed_bytes, Bip44Coins.NOSTR)
                      .Purpose()
                      .Coin()
                      .Account(0)
                      .Change(Bip44Changes.CHAIN_EXT)
                      .AddressIndex(0))
    # npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu
    print(bip44_addr_ctx.PublicKey().ToAddress())
    # nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp
    print(NostrNsecEncoder.Encode(bip44_addr_ctx.PrivateKey().Raw().ToBytes()))
