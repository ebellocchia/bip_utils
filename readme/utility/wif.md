## WIF

The WIF library allows encoding/decoding secp256k1 private keys in WIF format, both with compressed and uncompressed mode.\
`ValueError` is raised in case of errors.

**Code example**

    import binascii
    from bip_utils import Bip44Conf, CoinsConf, Secp256k1PrivateKey, WifPubKeyModes, WifDecoder, WifEncoder

    # Private key bytes or a private key object can be used
    priv_key = binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67')
    priv_key = Secp256k1PrivateKey.FromBytes(binascii.unhexlify(b'1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67'))

    # Encode/Decode with default parameters (Bitcoin main net, compressed public key)
    enc = WifEncoder.Encode(priv_key)
    dec, pub_key_mode = WifDecoder.Decode(enc)
    # Specify the public key mode (it's returned by the decoding method as second element)
    enc = WifEncoder.Encode(priv_key, pub_key_mode=WifPubKeyModes.COMPRESSED)
    enc = WifEncoder.Encode(priv_key, pub_key_mode=WifPubKeyModes.UNCOMPRESSED)
    dec, pub_key_mode = WifDecoder.Decode(enc)
    # Encode/Decode with net version from configuration
    enc = WifEncoder.Encode(priv_key,
                            CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"))
    dec, pub_key_mode = WifDecoder.Decode(enc,
                                          CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"))
    # Encode/Decode with net version from BIP
    enc = WifEncoder.Encode(priv_key,
                            Bip44Conf.BitcoinMainNet.WifNetVersion())
    dec, pub_key_mode = WifDecoder.Decode(enc,
                                          Bip44Conf.BitcoinMainNet.WifNetVersion())
    # Encode/Decode with custom net version
    enc = WifEncoder.Encode(priv_key,
                            b"\x00")
    dec, pub_key_mode = WifDecoder.Decode(enc,
                                          b"\x00")
