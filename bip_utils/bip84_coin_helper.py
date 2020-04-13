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
from .bip_coin_helper_base import CoinHelperBase
from .bip_coin_conf        import *
from .P2WPKH               import P2WPKH


class Bip84BitcoinHelper(CoinHelperBase):
    """ Bitcoin class. It contains the constants some helper methods for BIP-0084 Bitcoin. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return BitcoinConf.BIP84_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return BitcoinConf.BIP84_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return BitcoinConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return BitcoinConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (BipPublicKey)      : BipPublicKey object
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = BitcoinConf.P2WPKH_NET_VER["main"] if not is_testnet else BitcoinConf.P2WPKH_NET_VER["test"]
        return P2WPKH.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)


class Bip84LitecoinHelper(CoinHelperBase):
    """ Litecoin class. It contains the constants some helper methods for BIP-0084 Litecoin. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return LitecoinConf.BIP84_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return LitecoinConf.BIP84_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return LitecoinConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return LitecoinConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (BipPublicKey)      : BipPublicKey object
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = LitecoinConf.P2WPKH_NET_VER["main"] if not is_testnet else LitecoinConf.P2WPKH_NET_VER["test"]
        return P2WPKH.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)
