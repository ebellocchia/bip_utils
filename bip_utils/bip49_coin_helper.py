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


# Imports
import binascii
from .bip_coin_conf import *
from .P2SH          import P2SH


class BitcoinHelper:
    """ Bitcoin class. It contains the constants some helper methods for BIP-0049 Bitcoin. """

    # Main net versions (ypub / yprv)
    MAIN_NET_VER = {"pub" : binascii.unhexlify(b"049d7cb2"), "priv" : binascii.unhexlify(b"049d7878")}
    # Test net versions (upub / uprv)
    TEST_NET_VER = {"pub" : binascii.unhexlify(b"044a5262"), "priv" : binascii.unhexlify(b"044a4e28")}

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return BitcoinHelper.MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return BitcoinHelper.TEST_NET_VER

    @staticmethod
    def GetWifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return BitcoinConf.WIF_NET_VER

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2SH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key bytes
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = BitcoinConf.P2SH_NET_VER["main"] if not is_testnet else BitcoinConf.P2SH_NET_VER["test"]
        return P2SH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class LitecoinHelper:
    """ Litecoin class. It contains the constants some helper methods for BIP-0049 Litecoin. """

    # Main net versions (same of Bitcoin)
    MAIN_NET_VER     = BitcoinHelper.MAIN_NET_VER
    # Alternate main net versions (Mtpv / Mtub)
    ALT_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"01b26ef6"), "priv" : binascii.unhexlify(b"01b26792")}
    # Test net versions (ttub / ttpv)
    TEST_NET_VER     = {"pub" : binascii.unhexlify(b"0436f6e1"), "priv" : binascii.unhexlify(b"0436ef7d")}

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return LitecoinHelper.MAIN_NET_VER if not LitecoinConf.EX_KEY_ALT else LitecoinHelper.ALT_MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return LitecoinHelper.TEST_NET_VER

    @staticmethod
    def GetWifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return LitecoinConf.WIF_NET_VER

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2SH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key bytes
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        p2sh_ver = LitecoinConf.P2SH_NET_VER if not LitecoinConf.P2SH_DEPR_ADDR else LitecoinConf.P2SH_DEPR_NET_VER
        addr_ver = p2sh_ver["main"] if not is_testnet else p2sh_ver["test"]
        return P2SH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class DashHelper:
    """ Dash class. It contains the constants some helper methods for BIP-0049 Dash. """

    # Main net versions (same of Bitcoin)
    MAIN_NET_VER = BitcoinHelper.MAIN_NET_VER
    # Test net versions (same of Bitcoin)
    TEST_NET_VER = BitcoinHelper.TEST_NET_VER

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return DashHelper.MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return DashHelper.TEST_NET_VER

    @staticmethod
    def GetWifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return DashConf.WIF_NET_VER

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2SH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key bytes
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = DashConf.P2SH_NET_VER["main"] if not is_testnet else DashConf.P2SH_NET_VER["test"]
        return P2SH.ToAddress(pub_key.to_string("compressed"), addr_ver)
