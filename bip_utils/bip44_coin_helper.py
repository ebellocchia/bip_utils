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
from .P2PKH                import P2PKH
from .eth_addr             import EthAddr
from .xrp_addr             import XrpAddr


class BitcoinHelper(CoinHelperBase):
    """ Bitcoin helper class. It contains the constants some helper methods for BIP-0044 Bitcoin. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return BitcoinConf.BIP44_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return BitcoinConf.BIP44_TEST_NET_VER

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
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = BitcoinConf.P2PKH_NET_VER["main"] if not is_testnet else BitcoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class LitecoinHelper(CoinHelperBase):
    """ Litecoin class. It contains the constants some helper methods for BIP-0044 Litecoin. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return LitecoinConf.BIP44_MAIN_NET_VER if not LitecoinConf.EX_KEY_ALT else LitecoinConf.BIP44_ALT_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return LitecoinConf.BIP44_TEST_NET_VER

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
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = LitecoinConf.P2PKH_NET_VER["main"] if not is_testnet else LitecoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class DogecoinHelper(CoinHelperBase):
    """ Dogecoin class. It contains the constants some helper methods for BIP-0044 Dogecoin. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return DogecoinConf.BIP44_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return DogecoinConf.BIP44_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return DogecoinConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return DogecoinConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = DogecoinConf.P2PKH_NET_VER["main"] if not is_testnet else DogecoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class DashHelper(CoinHelperBase):
    """ Dash class. It contains the constants some helper methods for BIP-0044 Dash. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return DashConf.BIP44_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return DashConf.BIP44_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return DashConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return DashConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = DashConf.P2PKH_NET_VER["main"] if not is_testnet else DashConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class EthereumHelper(CoinHelperBase):
    """ Ethereum class. It contains the constants some helper methods for BIP-0044 Ethereum. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return EthereumConf.BIP44_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return EthereumConf.BIP44_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return EthereumConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return EthereumConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        # Ethereum uses the uncompressed key
        return EthAddr.ToAddress(pub_key.to_string("uncompressed")[1:])


class RippleHelper(CoinHelperBase):
    """ Ripple class. It contains the constants some helper methods for BIP-0044 Ripple. """

    @staticmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return RippleConf.BIP44_MAIN_NET_VER

    @staticmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return RippleConf.BIP44_TEST_NET_VER

    @staticmethod
    def WifNetVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        return RippleConf.WIF_NET_VER

    @staticmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return RippleConf.NAMES

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Compute address from public key.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        return XrpAddr.ToAddress(pub_key.to_string("compressed"))
