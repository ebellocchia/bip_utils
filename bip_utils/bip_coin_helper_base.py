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
from abc            import ABC, abstractmethod
from .bip_coin_conf import *


class CoinHelperBase(ABC):
    """ Bitcoin class. It contains the constants some helper methods for BIP-0044 Bitcoin. """

    @staticmethod
    @abstractmethod
    def MainNetVersions():
        """ Get main net versions.

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        pass

    @staticmethod
    @abstractmethod
    def TestNetVersions():
        """ Get test net versions.

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        pass

    @staticmethod
    @abstractmethod
    def WifVersions():
        """ Get WIF net versions.

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        pass

    @staticmethod
    @abstractmethod
    def CoinNames():
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        pass

    @staticmethod
    @abstractmethod
    def ComputeAddress(pub_key, is_testnet):
        """ Compute address from public key.

        Args:
            pub_key (BipPublicKey) : BipPublicKey object
            is_testnet (bool)      : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        pass
