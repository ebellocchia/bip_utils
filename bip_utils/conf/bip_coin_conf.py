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
    KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"0488b21e", b"0488ade4"),
                                           KeyNetVersions(b"043587cf", b"04358394"))


class BitcoinConf:
    """ Class container for Bitcoin configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Bitcoin", "BTC")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Bitcoin TestNet", "BTC")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER: NetVersions = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                                 KeyNetVersions(b"044a5262", b"044a4e28"))
    # BIP84 net versions (zpub / zprv) -  (vpub / vprv)
    BIP84_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"04b24746", b"04b2430c"),
                                                 KeyNetVersions(b"045f1cf6", b"045f18bc"))

    # Versions for P2PKH address
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x00", b"\x6f")
    # Versions for P2SH address
    P2SH_NET_VER: NetVersions = NetVersions(b"\x05", b"\xc4")
    # Versions for P2WPKH address
    P2WPKH_NET_VER: NetVersions = NetVersions("bc", "tb")
    # WIF net version
    WIF_NET_VER: NetVersions = NetVersions(b"\x80", b"\xef")


class BitcoinCashConf:
    """ Class container for Bitcoin Cash configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Bitcoin Cash", "BCH")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Bitcoin Cash TestNet", "BCH")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # False for using Bitcoin Cash addresses, True for using Bitcoin legacy addresses
    LEGACY_ADDR: bool = False

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER: NetVersions = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                                 KeyNetVersions(b"044a5262", b"044a4e28"))

    # Versions for P2PKH address (Bitcoin Cash has HRP and net version)
    BCH_P2PKH_NET_VER: NetVersions = NetVersions({"hrp": "bitcoincash", "net_ver": b"\x00"},
                                                 {"hrp": "bchtest", "net_ver": b"\x00"})
    # Versions for P2PKH legacy address (same of Bitcoin)
    LEGACY_P2PKH_NET_VER: NetVersions = BitcoinConf.P2PKH_NET_VER
    # Versions for P2SH address (Bitcoin Cash has HRP and net version)
    BCH_P2SH_NET_VER: NetVersions = NetVersions({"hrp": "bitcoincash", "net_ver": b"\x08"},
                                                {"hrp": "bchtest", "net_ver": b"\x08"})
    # Versions for P2PKH legacy address (same of Bitcoin)
    LEGACY_P2SH_NET_VER: NetVersions = BitcoinConf.P2SH_NET_VER
    # WIF net version
    WIF_NET_VER: NetVersions = NetVersions(b"\x80", b"\xef")


class BitcoinSvConf:
    """ Class container for BitcoinSV configuration. """

    # Names
    NAMES: CoinNames = CoinNames("BitcoinSV", "BSV")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("BitcoinSV TestNet", "BSV")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of BIP32)
    BIP44_KEY_NET_VER: NetVersions = Bip32Conf.KEY_NET_VER
    # BIP49 net versions (ypub / yprv) - (upub / uprv)
    BIP49_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"049d7cb2", b"049d7878"),
                                                 KeyNetVersions(b"044a5262", b"044a4e28"))

    # Versions for P2PKH address (same of Bitcoin)
    P2PKH_NET_VER: NetVersions = BitcoinConf.P2PKH_NET_VER
    # Versions for P2SH address (same of Bitcoin)
    P2SH_NET_VER: NetVersions = BitcoinConf.P2SH_NET_VER
    # WIF net version (same of Bitcoin)
    WIF_NET_VER: NetVersions = BitcoinConf.WIF_NET_VER


class LitecoinConf:
    """ Class container for Litecoin configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Litecoin", "LTC")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Litecoin TestNet", "LTC")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # False for using Bitcoin net versions for extended keys (xprv/xpub and similar)
    # True for using the alternate ones (Ltpv/Ltub and similar)
    EX_KEY_ALT: bool = False
    # False for using P2SH deprecated addresses, true for the new addresses
    P2SH_DEPR_ADDR: bool = False

    # BIP44 net versions
    # Litecoin can have 2 different main version: same of Bitcoin or (Ltpv / Ltub),
    # whereas test net version is always (ttub / ttpv)
    BIP44_KEY_NET_VER: NetVersions = NetVersions(
        {"btc": BitcoinConf.BIP44_KEY_NET_VER.Main(), "alt": KeyNetVersions(b"019da462", b"019d9cfe")},
        KeyNetVersions(b"0436f6e1", b"0436ef7d"))
    # BIP49 net versions
    # Litecoin can have 2 different main version: same of Bitcoin or (Mtpv / Mtub),
    # whereas test net version is always (ttub / ttpv)
    BIP49_KEY_NET_VER: NetVersions = NetVersions(
        {"btc": BitcoinConf.BIP49_KEY_NET_VER.Main(), "alt": KeyNetVersions(b"01b26ef6", b"01b26792")},
        KeyNetVersions(b"0436f6e1", b"0436ef7d"))
    # BIP84 net versions (zpub / zprv) - (ttub / ttpv)
    BIP84_KEY_NET_VER: NetVersions = NetVersions(BitcoinConf.BIP84_KEY_NET_VER.Main(),
                                                 KeyNetVersions(b"0436f6e1", b"0436ef7d"))

    # Versions for P2PKH address
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x30", b"\x6f")
    # Deprecated versions for P2SH address (same of Bitcoin)
    P2SH_DEPR_NET_VER: NetVersions = BitcoinConf.P2SH_NET_VER
    # Versions for P2SH address
    P2SH_NET_VER: NetVersions = NetVersions(b"\x32", b"\x3a")
    # Versions for P2WPKH address
    P2WPKH_NET_VER: NetVersions = NetVersions("ltc", "tltc")
    # WIF net version
    WIF_NET_VER: NetVersions = NetVersions(b"\xb0", b"\xef")


class DogecoinConf:
    """ Class container for Dogecoin configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Dogecoin", "DOGE")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Dogecoin TestNet", "DOGE")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (dgub / dgpv) - (tgub / tgpv)
    BIP44_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"02facafd", b"02fac398"),
                                                 KeyNetVersions(b"0432a9a8", b"0432a243"))
    # BIP49 net versions (dgub / dgpv) - (tgub / tgpv)
    BIP49_KEY_NET_VER: NetVersions = NetVersions(KeyNetVersions(b"02facafd", b"02fac398"),
                                                 KeyNetVersions(b"0432a9a8", b"0432a243"))

    # Versions for P2PKH address
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x1e", b"\x71")
    # Versions for P2SH address
    P2SH_NET_VER: NetVersions = NetVersions(b"\x16", b"\xc4")
    # WIF net version
    WIF_NET_VER: NetVersions = NetVersions(b"\x9e", b"\xf1")


class DashConf:
    """ Class container for Dash configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Dash", "DASH")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Dash TestNet", "DASH")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER
    # BIP49 net versions (same of Bitcoin)
    BIP49_KEY_NET_VER: NetVersions = BitcoinConf.BIP49_KEY_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x4c", b"\x8c")
    # Versions for P2SH address
    P2SH_NET_VER: NetVersions = NetVersions(b"\x10", b"\x13")
    # WIF net version
    WIF_NET_VER: NetVersions = NetVersions(b"\xcc", b"\xef")


class ZcashConf:
    """ Class container for Zcash configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Zcash", "ZEC")
    # Test names
    TEST_NAMES: CoinNames = CoinNames("Zcash TestNet", "ZEC")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER
    # BIP49 net versions (same of Bitcoin)
    BIP49_KEY_NET_VER: NetVersions = BitcoinConf.BIP49_KEY_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x1c\xb8", b"\x1d\x25")
    # Versions for P2SH address
    P2SH_NET_VER: NetVersions = NetVersions(b"\x1c\xbd", b"\x1c\xba")
    # WIF net version
    WIF_NET_VER: NetVersions = BitcoinConf.WIF_NET_VER


class EthereumConf:
    """ Class container for Ethereum configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Ethereum", "ETH")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class EthereumClassicConf:
    """ Class container for Ethereum Classic configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Ethereum Classic", "ETC")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class RippleConf:
    """ Class container for Ripple configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Ripple", "XRP")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # Versions for P2PKH address, test net not supported
    P2PKH_NET_VER: NetVersions = NetVersions(b"\x00")
    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class TronConf:
    """ Class container for Tron configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Tron", "TRX")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class VeChainConf:
    """ Class container for VeChain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("VeChain", "VET")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class CosmosConf:
    """ Class container for Cosmos configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Cosmos", "ATOM")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("cosmos")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class BandProtocolConf:
    """ Class container for Band Protocol configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Band Protocol", "BAND")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER: NetVersions = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("band")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class KavaConf:
    """ Class container for Kava configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Kava", "KAVA")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("kava")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class IrisNetConf:
    """ Class container for IRIS network configuration. """

    # Names
    NAMES: CoinNames = CoinNames("IRIS Network", "IRIS")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("iaa")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class TerraConf:
    """ Class container for Terra configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Terra", "LUNA")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("terra")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class BinanceChainConf:
    """ Class container for Binance Coin configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Binance Chain", "BNB")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # HRP for address
    ADDR_HRP: NetVersions = NetVersions("bnb")

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class BinanceSmartChainConf:
    """ Class container for Binance Smart Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Binance Smart Chain", "BNB")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class AvaxCChainConf:
    """ Class container for Avax C-Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Avax C-Chain", "AVAX")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class AvaxXChainConf:
    """ Class container for Avax X-Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Avax X-Chain", "AVAX")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class AvaxPChainConf:
    """ Class container for Avax P-Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Avax P-Chain", "AVAX")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class PolygonConf:
    """ Class container for Polygon configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Polygon", "MATIC")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class FantomOperaConf:
    """ Class container for Fantom Opera configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Fantom Opera", "FTM")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class HarmonyOneConf:
    """ Class container for Harmony One configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Harmony One", "ONE")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class HuobiChainConf:
    """ Class container for Huobi Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Huobi Token", "HT")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class OkexChainConf:
    """ Class container for OKEx Chain configuration. """

    # Names
    NAMES: CoinNames = CoinNames("OKExChain", "OKT")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class SolanaConf:
    """ Class container for Solana configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Solana", "SOL")

    # Default path
    DEFAULT_PATH: str = "0'"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class TezosConf:
    """ Class container for Tezos configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Tezos", "XTZ")

    # Default path
    DEFAULT_PATH: str = "0'/0'"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()


class NineChroniclesGoldConf:
    """ Class container for NCG configuration. """

    # Names
    NAMES: CoinNames = CoinNames("Nine Chronicles Gold", "NCG")

    # Default path
    DEFAULT_PATH: str = "0'/0/0"

    # BIP44 net versions (same of Bitcoin)
    BIP44_KEY_NET_VER = BitcoinConf.BIP44_KEY_NET_VER

    # WIF not supported
    WIF_NET_VER: NetVersions = NetVersions()
