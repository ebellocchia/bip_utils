## Addresses encoding/decoding

These libraries are used internally by the other modules, but they are available also for external use.\
When decoding an address, *ValueError* will be raised in case the encoding is not valid.\
So, to validate an address, just try to decode it and catch the *ValueError* exception.

**Code example**

    import binascii
    from bip_utils import *
    
    #
    # Addresses that require a secp256k1 curve
    #
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2")
    pub_key = Secp256k1PublicKey.FromBytes(
        binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2")
    )
    
    # P2PKH address with parameters from generic configuration
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      net_ver=CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver"))
    # Or with custom parameters
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      net_ver=b"\x01")
    # Or simply with the default parameters from BIP:
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      **Bip44Conf.BitcoinMainNet.AddrParams())
    # Same as before for decoding
    pub_key_hash = P2PKHAddrDecoder.DecodeAddr(addr,
                                               net_ver=CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver"))
    
    # Same for P2SH 
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     net_ver=CoinsConf.BitcoinMainNet.Params("p2sh_net_ver"))
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     net_ver=b"\x01")
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     **Bip49Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2SHAddrDecoder.DecodeAddr(addr,
                                              net_ver=CoinsConf.BitcoinMainNet.Params("p2sh_net_ver"))
    # Same for P2WPKH
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       hrp=CoinsConf.BitcoinMainNet.Params("p2wpkh_hrp"))
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       hrp="hrp")
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       **Bip84Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2WPKHAddrDecoder.DecodeAddr(addr,
                                                hrp=CoinsConf.BitcoinMainNet.Params("p2wpkh_hrp"))
    # Same for P2TR
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     hrp=CoinsConf.BitcoinMainNet.Params("p2tr_hrp"))
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     hrp="hrp")
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     **Bip86Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2TRAddrDecoder.DecodeAddr(addr,
                                              hrp=CoinsConf.BitcoinMainNet.Params("p2tr_hrp"))
    
    # P2PKH address in Bitcoin Cash format with parameters from generic configuration
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         hrp=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
                                         net_ver=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"))
    # Or with custom parameters
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         hrp="hrp",
                                         net_ver=b"\x01")
    # Or with the default parameters from BIP configuration:
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         **Bip44Conf.BitcoinCashMainNet.AddrParams())
    # Same as before for decoding
    pub_key_hash = BchP2PKHAddrDecoder.DecodeAddr(addr,
                                                  hrp=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
                                                  net_ver=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"))
    # Same for P2SH
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        hrp=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
                                        net_ver=CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"))
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        hrp="hrp",
                                        net_ver=b"\x01")
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        **Bip49Conf.BitcoinCashMainNet.AddrParams())
    pub_key_hash = BchP2SHAddrDecoder.DecodeAddr(addr,
                                                 hrp=CoinsConf.BitcoinCashMainNet.Params("p2sh_std_hrp"),
                                                 net_ver=CoinsConf.BitcoinCashMainNet.Params("p2sh_std_net_ver"))
    
    # Ethereum address
    # Checksum encoding can be skipped to get a lower case address
    addr = EthAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = EthAddrDecoder.DecodeAddr(addr)
    addr = EthAddrEncoder.EncodeKey(pub_key, skip_chksum_enc=True)
    pub_key_hash = EthAddrDecoder.DecodeAddr(addr, skip_chksum_enc=True)
    # Tron address
    addr = TrxAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = TrxAddrDecoder.DecodeAddr(addr)
    # AVAX address
    addr = AvaxPChainAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = AvaxPChainAddrDecoder.DecodeAddr(addr)
    addr = AvaxXChainAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = AvaxXChainAddrDecoder.DecodeAddr(addr)
    # Atom addresses with parameters from generic configuration
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     hrp=CoinsConf.Cosmos.Params("addr_hrp"))
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     hrp=CoinsConf.BinanceChain.Params("addr_hrp"))
    # Or with custom parameters
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     hrp="custom")
    # Or with the default parameters from BIP configuration:
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     **Bip44Conf.Cosmos.AddrParams())
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     **Bip44Conf.Kava.AddrParams())
    # Same as before for decoding
    pub_key_hash = AtomAddrDecoder.DecodeAddr(addr,
                                              hrp=CoinsConf.Kava.Params("addr_hrp"))
    
    # Filecoin address
    addr = FilSecp256k1AddrEncoder.EncodeKey(pub_key)
    pub_key_hash = FilSecp256k1AddrDecoder.DecodeAddr(addr)
    # OKEx Chain address
    addr = OkexAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = OkexAddrDecoder.DecodeAddr(addr)
    # Harmony One address
    addr = OneAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = OneAddrDecoder.DecodeAddr(addr)
    # Ripple address
    addr = XrpAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = XrpAddrDecoder.DecodeAddr(addr)
    # Zilliqa address
    addr = ZilAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = ZilAddrDecoder.DecodeAddr(addr)
    
    #
    # Addresses that require a ed25519 curve
    #
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519PublicKey.FromBytes(
        binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))
    
    # Algorand address
    addr = AlgoAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = AlgoAddrDecoder.DecodeAddr(addr)
    # Elrond address
    addr = EgldAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = EgldAddrDecoder.DecodeAddr(addr)
    
    # Solana address
    addr = SolAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = SolAddrDecoder.DecodeAddr(addr)
    
    # Stellar address with custom parameters
    addr = XlmAddrEncoder.EncodeKey(pub_key,
                                    addr_type=XlmAddrTypes.PUB_KEY)
    # Or with the default parameters from BIP configuration:
    addr = XlmAddrEncoder.EncodeKey(pub_key,
                                    **Bip44Conf.Stellar.AddrParams())
    # Same as before for decoding
    pub_key_bytes = XlmAddrDecoder.DecodeAddr(addr,
                                              addr_type=XlmAddrTypes.PUB_KEY)
    
    # Substrate address with parameters from generic configuration
    addr = SubstrateEd25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=CoinsConf.Polkadot.Params("addr_ss58_format"))
    # Or with custom parameters
    addr = SubstrateEd25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=5)
    
    # Or with the default parameters from BIP/Substrate:
    addr = SubstrateEd25519AddrEncoder.EncodeKey(pub_key,
                                                 **Bip44Conf.PolkadotEd25519Slip.AddrParams())
    addr = SubstrateEd25519AddrEncoder.EncodeKey(pub_key,
                                                 **SubstrateConf.Polkadot.AddrParams())
    # Same as before for decoding
    pub_key_bytes = SubstrateEd25519AddrDecoder.DecodeAddr(addr,
                                                           ss58_format=CoinsConf.Polkadot.Params("addr_ss58_format"))
    
    # Tezos address with custom parameters
    addr = XtzAddrEncoder.EncodeKey(pub_key,
                                    prefix=XtzAddrPrefixes.TZ1)
    # Or with the default parameters from BIP configuration:
    addr = XtzAddrEncoder.EncodeKey(pub_key,
                                    **Bip44Conf.Tezos.AddrParams())
    # Same as before for decoding
    pub_key_hash = XtzAddrDecoder.DecodeAddr(addr,
                                             prefix=XtzAddrPrefixes.TZ1)
    
    #
    # Addresses that require a ed25519-blake2b curve
    #
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519Blake2bPublicKey.FromBytes(
        binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    )
    
    # Nano address
    addr = NanoAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = NanoAddrDecoder.DecodeAddr(addr)
    
    #
    # Addresses that require a ed25519-monero curve
    #
    
    # Public key bytes or a public key object can be used
    pub_skey = binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422")
    pub_skey = Ed25519MoneroPublicKey.FromBytes(
        binascii.unhexlify(b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422")
    )
    pub_vkey = binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5")
    pub_vkey = Ed25519MoneroPublicKey.FromBytes(
        binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5")
    )
    
    # Monero address
    addr = XmrAddrEncoder.EncodeKey(pub_skey,
                                    pub_vkey=pub_vkey,
                                    net_ver=CoinsConf.MoneroMainNet.Params("addr_net_ver"))
    # Equivalent
    addr = XmrAddrEncoder.EncodeKey(pub_skey,
                                    pub_vkey=pub_vkey,
                                    net_ver=MoneroConf.MainNet.AddrNetVersion())
    # Decoding
    pub_key_bytes = XmrAddrDecoder.DecodeAddr(addr,
                                              net_ver=CoinsConf.MoneroMainNet.Params("addr_net_ver"))
    
    # Monero integrated address
    addr = XmrIntegratedAddrEncoder.EncodeKey(pub_skey,
                                              pub_vkey=pub_vkey,
                                              net_ver=CoinsConf.MoneroMainNet.Params("addr_int_net_ver"),
                                              payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    # Equivalent
    addr = XmrIntegratedAddrEncoder.EncodeKey(pub_skey,
                                              pub_vkey=pub_vkey,
                                              net_ver=MoneroConf.MainNet.IntegratedAddrNetVersion(),
                                              payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    # Decoding
    pub_key_bytes = XmrIntegratedAddrDecoder.DecodeAddr(addr,
                                                        net_ver=CoinsConf.MoneroMainNet.Params("addr_int_net_ver"),
                                                        payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    
    #
    # Addresses that require a nist256p1 curve
    #
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b")
    pub_key = Nist256p1PublicKey.FromBytes(
        binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b"))
    
    # NEO address with parameters from generic configuration
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    ver=CoinsConf.Neo.Params("addr_ver"))
    # Or with custom parameters
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    ver=b"\x10")
    # Or with the default parameters from BIP configuration:
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    **Bip44Conf.Neo.AddrParams())
    # Same as before for decoding
    pub_key_hash = NeoAddrDecoder.DecodeAddr(addr,
                                             ver=CoinsConf.Neo.Params("addr_ver"))
    
    #
    # Addresses that require a sr25519 curve
    #
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Sr25519PublicKey.FromBytes(
        binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))
    
    # Substrate address (like before)
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=CoinsConf.Kusama.Params("addr_ss58_format"))
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=3)
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 **SubstrateConf.Kusama.AddrParams())
    pub_key_bytes = SubstrateSr25519AddrDecoder.DecodeAddr(addr,
                                                           ss58_format=CoinsConf.Kusama.Params("addr_ss58_format"))

For Bitcoin Cash, it's also possible to convert its addresses by changing the HRP and net version.

**Code example**

    from bip_utils import BchAddrConverter

    # Convert address by change the HRP (the old net version is maintained)
    conv_addr = BchAddrConverter.Convert("bitcoincash:qp90dvzptg759efdcd93s4dkdw0vuhlkmqlch7letq", "ergon")
    # Convert address by change both HRP and net version
    conv_addr = BchAddrConverter.Convert("bitcoincash:qp90dvzptg759efdcd93s4dkdw0vuhlkmqlch7letq", "customprefix", b"\x01")

## Solana SPL tokens

The SPL token library allows generating token account addresses for Solana SPl tokens.

**Code example**

    from bip_utils import SplToken
    
    wallet_addr = "GP5XXWmhT2UKetabxr57VSX9o9yWNtGYWykwUNiEhw74"
    
    # Get address for USDC token
    usdc_addr = SplToken.GetAssociatedTokenAddress(wallet_addr,
                                                   "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    print(usdc_addr)
    # Get address for Serum token
    srm_addr = SplToken.GetAssociatedTokenAddress(wallet_addr,
                                                  "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt")
    print(srm_addr)

## WIF

This library is used internally by the other modules, but it's available also for external use.

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
                            CoinsConf.BitcoinMainNet.Params("wif_net_ver"))
    dec, pub_key_mode = WifDecoder.Decode(enc,
                                          CoinsConf.BitcoinMainNet.Params("wif_net_ver"))
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

    # Specify public key mode
    enc = WifEncoder.Encode(priv_key,
                            CoinsConf.BitcoinMainNet.Params("wif_net_ver"))
    dec, pub_key_mode = WifDecoder.Decode(enc,
                                          CoinsConf.BitcoinMainNet.Params("wif_net_ver"))

## Base58

This library is used internally by the other modules, but it's available also for external use.\
It supports both normal encode/decode and check_encode/check_decode with Bitcoin and Ripple alphabets (if not specified, the Bitcoin one will be used by default):

|Alphabet|Enum|
|---|---|
|Bitcoin|*Base58Alphabets.BITCOIN*|
|Ripple|*Base58Alphabets.RIPPLE*|

**Code example**

    import binascii
    from bip_utils import Base58Alphabets, Base58Decoder, Base58Encoder, Base58XmrDecoder, Base58XmrEncoder

    data_bytes = binascii.unhexlify(b"636363")

    # Normal encode
    enc = Base58Encoder.Encode(data_bytes)
    # Check encode
    chk_enc = Base58Encoder.CheckEncode(data_bytes)

    # Normal decode
    dec = Base58Decoder.Decode(enc)
    # Check decode
    # Base58ChecksumError is raised if checksum verification fails
    # ValueError is raised in case of encoding errors
    chk_dec = Base58Decoder.CheckDecode(chk_enc)

    # Same as before with Ripple alphabet
    enc = Base58Encoder.Encode(data_bytes, Base58Alphabets.RIPPLE)
    chk_enc = Base58Encoder.CheckEncode(data_bytes, Base58Alphabets.RIPPLE)
    dec = Base58Decoder.Decode(enc, Base58Alphabets.RIPPLE)
    chk_dec = Base58Decoder.CheckDecode(chk_enc, Base58Alphabets.RIPPLE)

    # Encode/Decode using Monero variation
    enc = Base58XmrEncoder.Encode(data_bytes)
    dec = Base58XmrDecoder.Decode(enc)

## SS58

This library is used internally by the other modules, but it's available also for external use.\
It allows encoding/deconding in SS58 format (2-byte checksum).

**Code example**

    import binascii
    from bip_utils import SS58Decoder, SS58Encoder

    data_bytes = binascii.unhexlify(b"e92b4b43a62fa66293f315486d66a67076e860e2aad76acb8e54f9bb7c925cd9")

    # Encode
    enc = SS58Encoder.Encode(data_bytes, ss58_format=0)
    # Decode
    ss58_format, dec = SS58Decoder.Decode(enc)

## Bech32

This library is used internally by the other modules, but it's available also for external use.

**Code example**

    import binascii
    from bip_utils import (
        Bech32Decoder, Bech32Encoder, BchBech32Encoder, BchBech32Decoder, SegwitBech32Decoder, SegwitBech32Encoder
    )

    data_bytes = binascii.unhexlify(b'9c90f934ea51fa0f6504177043e0908da6929983')

    # Encode with bech32
    enc = Bech32Encoder.Encode("cosmos", data_bytes)
    # Decode with bech32
    # Bech32ChecksumError is raised if checksum verification fails
    # ValueError is raised  in case of encoding errors
    dec = Bech32Decoder.Decode("cosmos", enc)

    # Encode with segwit bech32
    enc = SegwitBech32Encoder.Encode("bc", 0, data_bytes)
    # Decode with segwit bech32
    wit_ver, wit_prog = SegwitBech32Decoder.Decode("bc", enc)

    # Encode with BCH bech32
    enc = BchBech32Encoder.Encode("bitcoincash", b"\x00", data_bytes)
    # Decode with BCH bech32
    net_ver, dec = BchBech32Decoder.Decode("bitcoincash", enc)
