## Address encoding/decoding

The address library allows encoding/decoding addresses for all the supported coins.\
`ValueError` is raised in case of errors.

**Code example (coins based on the secp256k1 curve)**

    import binascii
    from bip_utils import *
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2")
    pub_key = Secp256k1PublicKey.FromBytes(
        binascii.unhexlify(b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2")
    )
    
    # P2PKH address with parameters from generic configuration
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"))
    # Or with custom parameters
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      net_ver=b"\x01")
    # Or simply with the default parameters from BIP:
    addr = P2PKHAddrEncoder.EncodeKey(pub_key,
                                      **Bip44Conf.BitcoinMainNet.AddrParams())
    # Same as before for decoding
    pub_key_hash = P2PKHAddrDecoder.DecodeAddr(addr,
                                               net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"))
    
    # Same for P2SH 
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2sh_net_ver"))
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     net_ver=b"\x01")
    addr = P2SHAddrEncoder.EncodeKey(pub_key,
                                     **Bip49Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2SHAddrDecoder.DecodeAddr(addr,
                                              net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2sh_net_ver"))
    # Same for P2WPKH
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"))
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       hrp="hrp")
    addr = P2WPKHAddrEncoder.EncodeKey(pub_key,
                                       **Bip84Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2WPKHAddrDecoder.DecodeAddr(addr,
                                                hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"))
    # Same for P2TR
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp"))
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     hrp="hrp")
    addr = P2TRAddrEncoder.EncodeKey(pub_key,
                                     **Bip86Conf.BitcoinMainNet.AddrParams())
    pub_key_hash = P2TRAddrDecoder.DecodeAddr(addr,
                                              hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp"))
    
    # P2PKH address in Bitcoin Cash format with parameters from generic configuration
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         hrp=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                                         net_ver=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"))
    # Or with custom parameters
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         hrp="hrp",
                                         net_ver=b"\x01")
    # Or with the default parameters from BIP configuration:
    addr = BchP2PKHAddrEncoder.EncodeKey(pub_key,
                                         **Bip44Conf.BitcoinCashMainNet.AddrParams())
    # Same as before for decoding
    pub_key_hash = BchP2PKHAddrDecoder.DecodeAddr(addr,
                                                  hrp=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                                                  net_ver=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"))
    # Same for P2SH
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        hrp=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                                        net_ver=CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"))
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        hrp="hrp",
                                        net_ver=b"\x01")
    addr = BchP2SHAddrEncoder.EncodeKey(pub_key,
                                        **Bip49Conf.BitcoinCashMainNet.AddrParams())
    pub_key_hash = BchP2SHAddrDecoder.DecodeAddr(addr,
                                                 hrp=CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_hrp"),
                                                 net_ver=CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_net_ver"))
    
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
                                     hrp=CoinsConf.Cosmos.ParamByKey("addr_hrp"))
    addr = AtomAddrEncoder.EncodeKey(pub_key,
                                     hrp=CoinsConf.BinanceChain.ParamByKey("addr_hrp"))
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
                                              hrp=CoinsConf.Kava.ParamByKey("addr_hrp"))
    
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

**Code example (coins based on the ed25519 curve)**

    import binascii
    from bip_utils import *
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519PublicKey.FromBytes(
        binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))
    
    # Algorand address
    addr = AlgoAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = AlgoAddrDecoder.DecodeAddr(addr)
    # Aptos address
    addr = AptosAddrEncoder.EncodeKey(pub_key)
    pub_key_hash = AptosAddrDecoder.DecodeAddr(addr)
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
                                                 ss58_format=CoinsConf.Polkadot.ParamByKey("addr_ss58_format"))
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
                                                           ss58_format=CoinsConf.Polkadot.ParamByKey("addr_ss58_format"))
    
    # Tezos address with custom parameters
    addr = XtzAddrEncoder.EncodeKey(pub_key,
                                    prefix=XtzAddrPrefixes.TZ1)
    # Or with the default parameters from BIP configuration:
    addr = XtzAddrEncoder.EncodeKey(pub_key,
                                    **Bip44Conf.Tezos.AddrParams())
    # Same as before for decoding
    pub_key_hash = XtzAddrDecoder.DecodeAddr(addr,
                                             prefix=XtzAddrPrefixes.TZ1)

**Code example (coins based on the ed25519-blake2b curve)**
    
    import binascii
    from bip_utils import *

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Ed25519Blake2bPublicKey.FromBytes(
        binascii.unhexlify(b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    )
    
    # Nano address
    addr = NanoAddrEncoder.EncodeKey(pub_key)
    pub_key_bytes = NanoAddrDecoder.DecodeAddr(addr)

**Code example (coins based on the ed25519-monero curve)**

    import binascii
    from bip_utils import *

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
                                    net_ver=CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"))
    # Equivalent
    addr = XmrAddrEncoder.EncodeKey(pub_skey,
                                    pub_vkey=pub_vkey,
                                    net_ver=MoneroConf.MainNet.AddrNetVersion())
    # Decoding
    pub_key_bytes = XmrAddrDecoder.DecodeAddr(addr,
                                              net_ver=CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"))
    
    # Monero integrated address
    addr = XmrIntegratedAddrEncoder.EncodeKey(pub_skey,
                                              pub_vkey=pub_vkey,
                                              net_ver=CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
                                              payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    # Equivalent
    addr = XmrIntegratedAddrEncoder.EncodeKey(pub_skey,
                                              pub_vkey=pub_vkey,
                                              net_ver=MoneroConf.MainNet.IntegratedAddrNetVersion(),
                                              payment_id=binascii.unhexlify(b"d7af025ab223b74e"))
    # Decoding
    pub_key_bytes = XmrIntegratedAddrDecoder.DecodeAddr(addr,
                                                        net_ver=CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
                                                        payment_id=binascii.unhexlify(b"d7af025ab223b74e"))

**Code example (coins based on the ed25519-kholaw curve)**

    import binascii
    from bip_utils import *
    
    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"01f9256746c79ad5ba163ae677e3e3477471f0c3f8e1b5012c7a09f862e3972d")
    pub_key = Ed25519KholawPublicKey.FromBytes(
        binascii.unhexlify(b"0072629d389eabb6a4a6e35c9b0cab50b546b4a49a20d1d831956bd06098ba3370")
    )
    
    # ADA Byron Icarus address (a chain code is also required)
    chain_code = binascii.unhexlify(b"fa8397359cea983fe2195214e96b4d9f9bc31941d973a77d2d98ac77ea186db8")
    
    addr = AdaByronIcarusAddrEncoder.EncodeKey(pub_key, chain_code=chain_code)
    pub_key_hash = AdaByronAddrDecoder.DecodeAddr(addr)
    
    # ADA Byron legacy address (chain code and HD data are also required)
    hd_path_key = binascii.unhexlify(b"c582f8e7cf7aeb6e5f3e96e939a92ae1642360a51d45150f34e70132a152203f")
    
    addr = AdaByronLegacyAddrEncoder.EncodeKey(pub_key,
                                               chain_code=chain_code,
                                               hd_path="m/0'/0'",
                                               hd_path_key=hd_path_key)
    pub_key_hash = AdaByronAddrDecoder.DecodeAddr(addr)
    
    # ADA Shelley address (a staking key is also required)
    pub_skey = binascii.unhexlify(b"7680c767b8096daa3299dc282068327c79976f346e55b72d0ffd751295a45913")
    
    addr = AdaShelleyAddrEncoder.EncodeKey(pub_key,
                                           pub_skey=pub_skey,
                                           net_tag=AdaShelleyAddrNetworkTags.MAINNET)
    pub_key_hash = AdaShelleyAddrDecoder.DecodeAddr(addr)

**Code example (coins based on the nist256p1 curve)**

    import binascii
    from bip_utils import *

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b")
    pub_key = Nist256p1PublicKey.FromBytes(
        binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b"))
    
    # NEO address with parameters from generic configuration
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    ver=CoinsConf.Neo.ParamByKey("addr_ver"))
    # Or with custom parameters
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    ver=b"\x10")
    # Or with the default parameters from BIP configuration:
    addr = NeoAddrEncoder.EncodeKey(pub_key,
                                    **Bip44Conf.Neo.AddrParams())
    # Same as before for decoding
    pub_key_hash = NeoAddrDecoder.DecodeAddr(addr,
                                             ver=CoinsConf.Neo.ParamByKey("addr_ver"))

**Code example (coins based on the sr25519 curve)**

    import binascii
    from bip_utils import *

    # Public key bytes or a public key object can be used
    pub_key = binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832")
    pub_key = Sr25519PublicKey.FromBytes(
        binascii.unhexlify(b"dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832"))
    
    # Substrate address (like before)
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=CoinsConf.Kusama.ParamByKey("addr_ss58_format"))
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 ss58_format=3)
    addr = SubstrateSr25519AddrEncoder.EncodeKey(pub_key,
                                                 **SubstrateConf.Kusama.AddrParams())
    pub_key_bytes = SubstrateSr25519AddrDecoder.DecodeAddr(addr,
                                                           ss58_format=CoinsConf.Kusama.ParamByKey("addr_ss58_format"))
