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
import binascii


class Bip32Conf:
    """ Class container for Bip32 configuration. """

    # Main net versions (xpub / xprv)
    MAIN_NET_VER = {"pub" : binascii.unhexlify(b"0488b21e"), "priv" : binascii.unhexlify(b"0488ade4")}
    # Test net versions (tpub / tprv)
    TEST_NET_VER = {"pub" : binascii.unhexlify(b"043587CF"), "priv" : binascii.unhexlify(b"04358394")}


class BitcoinConf:
    """ Class container for Bitcoin configuration. """

    # Coin names
    NAMES              = {"name" : "Bitcoin", "abbr" : "BTC" }

    # BIP44 Main net versions (same of BIP32)
    BIP44_MAIN_NET_VER = Bip32Conf.MAIN_NET_VER
    # BIP44 Test net versions (same of BIP32)
    BIP44_TEST_NET_VER = Bip32Conf.TEST_NET_VER

    # BIP49 Main net versions (ypub / yprv)
    BIP49_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"049d7cb2"), "priv" : binascii.unhexlify(b"049d7878")}
    # BIP49 Test net versions (upub / uprv)
    BIP49_TEST_NET_VER = {"pub" : binascii.unhexlify(b"044a5262"), "priv" : binascii.unhexlify(b"044a4e28")}

    # BIP84 Main net versions (zpub / zprv)
    BIP84_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"04b24746"), "priv" : binascii.unhexlify(b"04b2430c")}
    # BIP84 Test net versions (vpub / vprv)
    BIP84_TEST_NET_VER = {"pub" : binascii.unhexlify(b"045f1cf6"), "priv" : binascii.unhexlify(b"045f18bc")}

    # Versions for P2PKH address
    P2PKH_NET_VER      = {"main" : b"\x00", "test" : b"\x6f"}
    # Versions for P2SH address
    P2SH_NET_VER       = {"main" : b"\x05", "test" : b"\xc4"}
    # Versions for P2WPKH address
    P2WPKH_NET_VER     = {"main" : "bc", "test" : "tb"}
    # WIF net version
    WIF_NET_VER        = {"main" : b"\x80", "test" : b"\xef"}


class LitecoinConf:
    """ Class container for Litecoin configuration. """

    # Coin names
    NAMES                  = {"name" : "Litecoin", "abbr" : "LTC" }

    # False for using Bitcoin net versions for extended keys (xprv/xpub and similar), true for using the alternate ones (Ltpv/Ltub and similar)
    EX_KEY_ALT             = False
    # False for using P2SH deprecated addresses, true for the new addresses
    P2SH_DEPR_ADDR         = False

    # BIP44 Main net versions (same of BIP32)
    BIP44_MAIN_NET_VER     = Bip32Conf.MAIN_NET_VER
    # BIP44 Alternate main net versions (Ltpv / Ltub)
    BIP44_ALT_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"019da462"), "priv" : binascii.unhexlify(b"019d9cfe")}
    # BIP44 Test net versions (ttub / ttpv)
    BIP44_TEST_NET_VER     = {"pub" : binascii.unhexlify(b"0436f6e1"), "priv" : binascii.unhexlify(b"0436ef7d")}

    # BIP49 Main net versions (same of Bitcoin)
    BIP49_MAIN_NET_VER     = BitcoinConf.BIP49_MAIN_NET_VER
    # BIP49 Alternate main net versions (Mtpv / Mtub)
    BIP49_ALT_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"01b26ef6"), "priv" : binascii.unhexlify(b"01b26792")}
    # BIP49 Test net versions (ttub / ttpv)
    BIP49_TEST_NET_VER     = {"pub" : binascii.unhexlify(b"0436f6e1"), "priv" : binascii.unhexlify(b"0436ef7d")}

    # BIP84 Main net versions (same of Bitcoin)
    BIP84_MAIN_NET_VER     = BitcoinConf.BIP84_MAIN_NET_VER
    # BIP84 Test net versions (ttub / ttpv)
    BIP84_TEST_NET_VER     = {"pub" : binascii.unhexlify(b"0436f6e1"), "priv" : binascii.unhexlify(b"0436ef7d")}

    # Versions for P2PKH address
    P2PKH_NET_VER          = {"main" : b"\x30", "test" : b"\x6f"}
    # Deprecated versions for P2SH address (same of Bitcoin)
    P2SH_DEPR_NET_VER      = BitcoinConf.P2SH_NET_VER
    # Versions for P2SH address
    P2SH_NET_VER           = {"main" : b"\x32", "test" : b"\x3a"}
    # Versions for P2WPKH address
    P2WPKH_NET_VER         = {"main" : "ltc", "test" : "tltc"}
    # WIF net version
    WIF_NET_VER            = {"main" : b"\xb0", "test" : b"\xef"}


class DogecoinConf:
    """ Class container for Dogecoin configuration. """

    # Coin names
    NAMES              = {"name" : "Dogecoin", "abbr" : "DOGE" }

    # BIP44 Main net versions (dgub / dgpv)
    BIP44_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"02facafd"), "priv" : binascii.unhexlify(b"02fac398")}
    # BIP44 Test net versions (tgub / tgpv)
    BIP44_TEST_NET_VER = {"pub" : binascii.unhexlify(b"0432a9a8"), "priv" : binascii.unhexlify(b"0432a243")}

    # BIP49 Main net versions (dgub / dgpv)
    BIP49_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"02facafd"), "priv" : binascii.unhexlify(b"02fac398")}
    # BIP49 Test net versions (tgub / tgpv)
    BIP49_TEST_NET_VER = {"pub" : binascii.unhexlify(b"0432a9a8"), "priv" : binascii.unhexlify(b"0432a243")}

    # Versions for P2PKH address
    P2PKH_NET_VER      = {"main" : b"\x1e", "test" : b"\x71"}
    # Versions for P2SH address
    P2SH_NET_VER       = {"main" : b"\x16", "test" : b"\xc4"}
    # WIF net version
    WIF_NET_VER        = {"main" : b"\x9e", "test" : b"\xf1"}


class DashConf:
    """ Class container for Dash configuration. """

    # Coin names
    NAMES              = {"name" : "Dash", "abbr" : "DASH" }

    # BIP44 Main net versions (same of BIP32)
    BIP44_MAIN_NET_VER = Bip32Conf.MAIN_NET_VER
    # BIP44 Test net versions (same of BIP32)
    BIP44_TEST_NET_VER = Bip32Conf.TEST_NET_VER

    # BIP49 Main net versions (same of Bitcoin)
    BIP49_MAIN_NET_VER = BitcoinConf.BIP49_MAIN_NET_VER
    # BIP49 Test net versions (same of Bitcoin)
    BIP49_TEST_NET_VER = BitcoinConf.BIP49_TEST_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER      = {"main" : b"\x4c", "test" : b"\x8c"}
    # Versions for P2SH address
    P2SH_NET_VER       = {"main" : b"\x10", "test" : b"\x13"}
    # WIF net version
    WIF_NET_VER        = {"main" : b"\xcc", "test" : b"\xef"}


class EthereumConf:
    """ Class container for Ethereum configuration. """

    # Coin names
    NAMES              = {"name" : "Ethereum", "abbr" : "ETH" }

    # BIP44 Main net versions (same of BIP32)
    BIP44_MAIN_NET_VER = Bip32Conf.MAIN_NET_VER
    # BIP44 Test net versions (same of BIP32)
    BIP44_TEST_NET_VER = Bip32Conf.TEST_NET_VER

    # WIF not supported
    WIF_NET_VER        = None


class RippleConf:
    """ Class container for Bitcoin configuration. """

    # Coin names
    NAMES              = {"name" : "Ripple", "abbr" : "XRP" }

    # BIP44 Main net versions (same of BIP32)
    BIP44_MAIN_NET_VER = Bip32Conf.MAIN_NET_VER
    # BIP44 Test net versions (same of BIP32)
    BIP44_TEST_NET_VER = Bip32Conf.TEST_NET_VER

    # Versions for P2PKH address
    P2PKH_NET_VER      = b"\x00"
    # WIF not supported
    WIF_NET_VER        = None
