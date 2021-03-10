# Copyright (c) 2020 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# It's not so easy to find this information, some references I used:
# https://github.com/libbitcoin/libbitcoin-system/wiki/Altcoin-Version-Mappings#bip44-altcoin-version-mapping-table
# https://github.com/satoshilabs/slips/blob/master/slip-0132.md


# Imports
from bip_utils.conf.bip_coin_conf_helper import *


class Bip32Conf:
    """ Class container for Bip32 configuration. """

    # Key net versions (xpub / xprv) - (tpub / tprv)
    KEY_NET_VER = NetVersions(KeyNetVersions(b"0488b21e", b"0488ade4"),
                              KeyNetVersions(b"043587cf", b"04358394"))


class BitcoinConf:
    """ Class container for Bitcoin configuration. """

    # Names
    NAMES             = CoinNames("Bitcoin"        , "BTC")
    # Test names
    TEST_NAMES        = CoinNames("Bitcoin TestNet", "BTC")

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                    KeyNetVersions(b"044a5262", b"044a4e28"))
    # BIP84 net versions (zpub / zprv) -  (vpub / vprv)
    BIP84_KEY_NET_VER = NetVersions(KeyNetVersions(b"04b24746", b"04b2430c"),
                                    KeyNetVersions(b"045f1cf6", b"045f18bc"))

    # Versions for P2PKH address
    P2PKH_NET_VER     = NetVersions(b"\x00", b"\x6f")
    # Versions for P2SH address
    P2SH_NET_VER      = NetVersions(b"\x05", b"\xc4")
    # Versions for P2WPKH address
    P2WPKH_NET_VER    = NetVersions("bc", "tb")
    # WIF net version
    WIF_NET_VER       = NetVersions(b"\x80", b"\xef")


class BitcoinCashConf:
    """ Class container for Bitcoin Cash configuration. """

    # Names
    NAMES                 = CoinNames("Bitcoin Cash"        , "BCH")
    # Test names
    TEST_NAMES            = CoinNames("Bitcoin Cash TestNet", "BCH")

    # False for using Bitcoin Cash addresses, True for using Bitcoin legacy addresses
    LEGACY_ADDR          = False

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER    = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER    = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                       KeyNetVersions(b"044a5262", b"044a4e28"))

    # Versions for P2PKH address (Bitcoin Cash has HRP and net version)
    BCH_P2PKH_NET_VER    = NetVersions({"hrp" : "bitcoincash", "net_ver" : b"\x00"},
                                       {"hrp" : "bchtest"    , "net_ver" : b"\x00"})
    # Versions for P2PKH legacy address (same of Bitcoin)
    LEGACY_P2PKH_NET_VER = BitcoinConf.P2PKH_NET_VER
    # Versions for P2SH address (Bitcoin Cash has HRP and net version)
    BCH_P2SH_NET_VER     = NetVersions({"hrp" : "bitcoincash", "net_ver" : b"\x08"},
                                       {"hrp" : "bchtest"    , "net_ver" : b"\x08"})
    # Versions for P2PKH legacy address (same of Bitcoin)
    LEGACY_P2SH_NET_VER  = BitcoinConf.P2SH_NET_VER
    # WIF net version
    WIF_NET_VER          = NetVersions(b"\x80", b"\xef")


class BitcoinSvConf:
    """ Class container for BitcoinSV configuration. """

    # Names
    NAMES             = CoinNames("BitcoinSV"        , "BSV")
    # Test names
    TEST_NAMES        = CoinNames("BitcoinSV TestNet", "BSV")

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                    KeyNetVersions(b"044a5262", b"044a4e28"))

    # Versions for P2PKH address (same of Bitcoin)
    P2PKH_NET_VER     = BitcoinConf.P2PKH_NET_VER
    # Versions for P2SH address (same of Bitcoin)
    P2SH_NET_VER      = BitcoinConf.P2SH_NET_VER
    # WIF net version (same of Bitcoin)
    WIF_NET_VER       = BitcoinConf.WIF_NET_VER


class LitecoinConf:
    """ Class container for Litecoin configuration. """

    # Names
    NAMES              = CoinNames("Litecoin"        , "LTC")
    # Test names
    TEST_NAMES         = CoinNames("Litecoin TestNet", "LTC")

    # False for using Bitcoin net versions for extended keys (xprv/xpub and similar), true for using the alternate ones (Ltpv/Ltub and similar)
    EX_KEY_ALT         = False
    # False for using P2SH deprecated addresses, true for the new addresses
    P2SH_DEPR_ADDR     = False

    # BIP44 net versions
    # Litecoin can have 2 different main version: same of Bitcoin or (Ltpv / Ltub), whereas test net version is always (ttub / ttpv)
    BIP44_KEY_NET_VER  = NetVersions({"btc" : BitcoinConf.BIP44_KEY_NET_VER.Main(), "alt" : KeyNetVersions(b"019da462", b"019d9cfe")},
                                     KeyNetVersions(b"0436f6e1", b"0436ef7d"))
    # BIP49 net versions
    # Litecoin can have 2 different main version: same of Bitcoin or (Mtpv / Mtub), whereas test net version is always (ttub / ttpv)
    BIP49_KEY_NET_VER  = NetVersions({"btc" : BitcoinConf.BIP49_KEY_NET_VER.Main(), "alt" : KeyNetVersions(b"01b26ef6", b"01b26792")},
                                     KeyNetVersions(b"0436f6e1", b"0436ef7d"))
    # BIP84 net versions (zpub / zprv) - (ttub / ttpv)
    BIP84_KEY_NET_VER  = NetVersions(BitcoinConf.BIP84_KEY_NET_VER.Main(),
                                     KeyNetVersions(b"0436f6e1", b"0436ef7d"))

    # Versions for P2PKH address
    P2PKH_NET_VER      = NetVersions(b"\x30", b"\x6f")
    # Deprecated versions for P2SH address (same of Bitcoin)
    P2SH_DEPR_NET_VER  = BitcoinConf.P2SH_NET_VER
    # Versions for P2SH address
    P2SH_NET_VER       = NetVersions(b"\x32", b"\x3a")
    # Versions for P2WPKH address
    P2WPKH_NET_VER     = NetVersions("ltc", "tltc")
    # WIF net version
    WIF_NET_VER        = NetVersions(b"\xb0", b"\xef")


class DogecoinConf:
    """ Class container for Dogecoin configuration. """

    # Names
    NAMES             = CoinNames("Dogecoin"        , "DOGE")
    # Test names
    TEST_NAMES        = CoinNames("Dogecoin TestNet", "DOGE")

    # BIP44 net versions (dgub / dgpv) - (tgub / tgpv)
    BIP44_KEY_NET_VER = NetVersions(KeyNetVersions(b"02facafd", b"02fac398"),
                                    KeyNetVersions(b"0432a9a8", b"0432a243"))
    # BIP49 net versions (dgub / dgpv) - (tgub / tgpv)
    BIP49_KEY_NET_VER = NetVersions(KeyNetVersions(b"02facafd", b"02fac398"),
                                    KeyNetVersions(b"0432a9a8", b"0432a243"))

    # Versions for P2PKH address
    P2PKH_NET_VER     = NetVersions(b"\x1e", b"\x71")
    # Versions for P2SH address
    P2SH_NET_VER      = NetVersions(b"\x16", b"\xc4")
    # WIF net version
    WIF_NET_VER       = NetVersions(b"\x9e", b"\xf1")


class DashConf:
    """ Class container for Dash configuration. """

    # Names
    NAMES             = CoinNames("Dash"        , "DASH")
    # Test names
    TEST_NAMES        = CoinNames("Dash TestNet", "DASH")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER
    # BIP49 net versions (same of Bitcoin)
    BIP49_KEY_NET_VER = BitcoinConf.BIP49_KEY_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER     = NetVersions(b"\x4c", b"\x8c")
    # Versions for P2SH address
    P2SH_NET_VER      = NetVersions(b"\x10", b"\x13")
    # WIF net version
    WIF_NET_VER       = NetVersions(b"\xcc", b"\xef")


class ZcashConf:
    """ Class container for Zcash configuration. """

    # Names
    NAMES             = CoinNames("Zcash", "ZEC")
    # Test names
    TEST_NAMES        = CoinNames("Zcash TestNet", "ZEC")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER
    # BIP49 net versions (same of Bitcoin)
    BIP49_KEY_NET_VER = BitcoinConf.BIP49_KEY_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER     = NetVersions(b"\x1c\xb8", b"\x1d\x25")
    # Versions for P2SH address
    P2SH_NET_VER      = NetVersions(b"\x1c\xbd", b"\x1c\xba")
    # WIF net version
    WIF_NET_VER       = BitcoinConf.WIF_NET_VER


class EthereumConf:
    """ Class container for Ethereum configuration. """

    # Names
    NAMES             = CoinNames("Ethereum", "ETH")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class EthereumClassicConf:
    """ Class container for Ethereum Classic configuration. """

    # Names
    NAMES             = CoinNames("Ethereum Classic", "ETC")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class RippleConf:
    """ Class container for Ripple configuration. """

    # Names
    NAMES             = CoinNames("Ripple", "XRP")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # Versions for P2PKH address, test net not supported
    P2PKH_NET_VER     = NetVersions(b"\x00")
    # WIF not supported
    WIF_NET_VER       = NetVersions()


class TronConf:
    """ Class container for Tron configuration. """

    # Names
    NAMES             = CoinNames("Tron", "TRX")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class VeChainConf:
    """ Class container for VeChain configuration. """

    # Names
    NAMES             = CoinNames("VeChain", "VET")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class CosmosConf:
    """ Class container for Cosmos configuration. """

    # Names
    NAMES             = CoinNames("Cosmos", "ATOM")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP          = NetVersions("cosmos")

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class BandProtocolConf:
    """ Class container for Band Protocol configuration. """

    # Names
    NAMES             = CoinNames("Band Protocol", "BAND")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP          = NetVersions("band")

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class KavaConf:
    """ Class container for Kava configuration. """

    # Names
    NAMES             = CoinNames("Kava", "KAVA")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP          = NetVersions("kava")

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class IrisNetConf:
    """ Class container for IRIS network configuration. """

    # Names
    NAMES             = CoinNames("IRIS Network", "IRIS")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP          = NetVersions("iaa")

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class BinanceChainConf:
    """ Class container for Binance Coin configuration. """

    # Names
    NAMES             = CoinNames("Binance Chain", "BNB")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP          = NetVersions("bnb")

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class BinanceSmartChainConf:
    """ Class container for Ethereum configuration. """

    # Names
    NAMES             = CoinNames("Binance Smart Chain", "BNB")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()


class NineChroniclesGoldConf:
    """ Class container for NCG configuration. """

    # Names
    NAMES             = CoinNames("Nine Chronicles Gold", "NCG")

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER       = NetVersions()
