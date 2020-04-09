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
from .              import utils
from .bip32         import Bip32Const
from .bip_coin_conf import *
from .P2PKH         import P2PKH
from .eth_addr      import EthAddr
from .xrp_addr      import XrpAddr


class BitcoinHelper():
    """ Bitcoin class. It contains the constants some helper methods for BIP-0044 Bitcoin. """

    # Main net versions (same of BIP32 for BIP44)
    MAIN_NET_VER = Bip32Const.MAIN_NET_VER
    # Test net versions (same of BIP32 for BIP44)
    TEST_NET_VER = Bip32Const.TEST_NET_VER

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
    def GetConfig():
        """ Get coin configuration.

        Returns (BitcoinConf):
            Coin configuration.
        """
        return BitcoinConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = BitcoinConf.P2PKH_NET_VER["main"] if not is_testnet else BitcoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class LitecoinHelper():
    """ Litecoin class. It contains the constants some helper methods for BIP-0044 Litecoin. """

    # Main net versions (same of BIP32)
    MAIN_NET_VER     = Bip32Const.MAIN_NET_VER
    # Alternate main net versions (Ltpv / Ltub)
    ALT_MAIN_NET_VER = {"pub" : binascii.unhexlify(b"019da462"), "priv" : binascii.unhexlify(b"019d9cfe")}
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
    def GetConfig():
        """ Get coin configuration.

        Returns (LitecoinConf):
            Coin configuration.
        """
        return LitecoinConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (bytes)       : ECDSA public key bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = LitecoinConf.P2PKH_NET_VER["main"] if not is_testnet else LitecoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class DogecoinHelper():
    """ Dogecoin class. It contains the constants some helper methods for BIP-0044 Dogecoin. """

    # Main net versions (dgub / dgpv)
    MAIN_NET_VER = {"pub" : binascii.unhexlify(b"02facafd"), "priv" : binascii.unhexlify(b"02fac398")}
    # Test net versions (tgub / tgpv)
    TEST_NET_VER = {"pub" : binascii.unhexlify(b"0432a9a8"), "priv" : binascii.unhexlify(b"0432a243")}

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return DogecoinHelper.MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return DogecoinHelper.TEST_NET_VER

    @staticmethod
    def GetConfig():
        """ Get coin configuration.

        Returns (DogecoinConf):
            Coin configuration.
        """
        return DogecoinConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key bytes
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = DogecoinConf.P2PKH_NET_VER["main"] if not is_testnet else DogecoinConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class DashHelper():
    """ Dash class. It contains the constants some helper methods for BIP-0044 Dash. """

    # Main net versions (same of BIP32 for BIP44)
    MAIN_NET_VER = Bip32Const.MAIN_NET_VER
    # Test net versions (same of BIP32 for BIP44)
    TEST_NET_VER = Bip32Const.TEST_NET_VER

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
    def GetConfig():
        """ Get coin configuration.

        Returns (DashConf):
            Coin configuration.
        """
        return DashConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = DashConf.P2PKH_NET_VER["main"] if not is_testnet else DashConf.P2PKH_NET_VER["test"]
        return P2PKH.ToAddress(pub_key.to_string("compressed"), addr_ver)


class EthereumHelper():
    """ Ethereum class. It contains the constants some helper methods for BIP-0044 Ethereum. """

    # Main net versions (same of BIP32 for Ethereum)
    MAIN_NET_VER = Bip32Const.MAIN_NET_VER
    # Main net versions (same of BIP32 for Ethereum)
    TEST_NET_VER = Bip32Const.TEST_NET_VER

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return EthereumHelper.MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return EthereumHelper.TEST_NET_VER

    @staticmethod
    def GetConfig():
        """ Get coin configuration.

        Returns (EthereumConf):
            Coin configuration.
        """
        return EthereumConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key bytes
            is_testnet (bool, optional)  : not used

        Returns (str):
            Address string
        """
        # Ethereum uses the uncompressed key
        return EthAddr.ToAddress(pub_key.to_string("uncompressed")[1:])


class RippleHelper():
    """ Ripple class. It contains the constants some helper methods for BIP-0044 Ripple. """

    # Main net versions (same of BIP32 for Ripple)
    MAIN_NET_VER = Bip32Const.MAIN_NET_VER
    # Main net versions (same of BIP32 for Ripple)
    TEST_NET_VER = Bip32Const.TEST_NET_VER

    @staticmethod
    def GetMainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return RippleHelper.MAIN_NET_VER

    @staticmethod
    def GetTestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return RippleHelper.TEST_NET_VER

    @staticmethod
    def GetConfig():
        """ Get coin configuration.

        Returns (RippleConf):
            Coin configuration.
        """
        return RippleConf

    @staticmethod
    def ComputeAddress(pub_key, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key (ecdsa.VerifyingKey) : ECDSA public key
            is_testnet (bool, optional)  : not used

        Returns (str):
            Address string
        """
        return XrpAddr.ToAddress(pub_key.to_string("compressed"))
