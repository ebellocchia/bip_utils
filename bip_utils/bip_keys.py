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
from .bip32_ex          import Bip32KeyError
from .bip32_key_ser     import Bip32KeySerializer
from .bip44_coin_helper import Bip44BitcoinHelper
from .wif               import WifEncoder
from .                  import utils


class BipKeyBytes:
    """ BIP key bytes class. It allows to get key bytes in different formats. """

    def __init__(self, key_bytes):
        """ Construct class.

        Args:
            key_bytes (bytes) : key bytes
        """
        self.m_key_bytes = key_bytes

    def ToBytes(self):
        """ Get key bytes.

        Returns (bytes):
            Key bytes
        """
        return self.m_key_bytes

    def ToHex(self):
        """ Get key bytes in hex format.

        Returns (str):
            Key bytes in hex format
        """
        return utils.BytesToString(self.m_key_bytes)


class BipPublicKey:
    """ BIP public key class. It allows to get a public key in different formats. """

    def __init__(self, bip32_obj, coin_helper = Bip44BitcoinHelper):
        """ Construct class.

        Args:
            bip32_obj (Bip32 object)                      : Bip32 object
            coin_helper (CoinHelperBase object, optional) : CoinHelperBase object, Bip44BitcoinHelper by default
        """
        self.m_bip32_obj   = bip32_obj
        self.m_coin_helper = coin_helper

    def RawCompressed(self):
        """ Return raw compressed public key.

        Returns (BipKeyBytes object):
            BipKeyBytes object
        """
        return BipKeyBytes(self.m_bip32_obj.EcdsaPublicKey().to_string("compressed"))

    def RawUncompressed(self):
        """ Return raw uncompressed public key.

        Returns (BipKeyBytes object):
            BipKeyBytes object
        """

        # The first byte is the version (0x04), it's not needed
        return BipKeyBytes(self.m_bip32_obj.EcdsaPublicKey().to_string("uncompressed")[1:])

    def ToExtended(self):
        """ Return key in serialized extended format.

        Returns (str):
            Key in serialized extended format
        """
        return Bip32KeySerializer(self.m_bip32_obj).SerializePublicKey(self.m_coin_helper.MainNetVersions()["pub"], self.m_coin_helper.TestNetVersions()["pub"])

    def ToAddress(self):
        """ Return address correspondent tot he public key.

        Returns (str):
            Address
        """
        return self.m_coin_helper.ComputeAddress(self, self.m_bip32_obj.IsTestNet())


class BipPrivateKey:
    """ BIP privte key class. It allows to get a privte key in different formats. """

    def __init__(self, bip32_obj, coin_helper = Bip44BitcoinHelper):
        """ Construct class.

        Args:
            bip32_obj (Bip32 object)                      : Bip32 object
            coin_helper (CoinHelperBase object, optional) : CoinHelperBase object, Bip44BitcoinHelper by default
        """
        if bip32_obj.IsPublicOnly():
            raise Bip32KeyError("Cannot create a private key form a public-only Bip32 object")

        self.m_bip32_obj   = bip32_obj
        self.m_coin_helper = coin_helper

    def Raw(self):
        """ Return raw private key.

        Returns (BipKeyBytes object):
            BipKeyBytes object
        """
        return BipKeyBytes(self.m_bip32_obj.EcdsaPrivateKey().to_string())

    def ToExtended(self):
        """ Return key in serialized extended format.

        Returns (str):
            Key in serialized extended format
        """
        return Bip32KeySerializer(self.m_bip32_obj).SerializePrivateKey(self.m_coin_helper.MainNetVersions()["priv"], self.m_coin_helper.TestNetVersions()["priv"])

    def ToWif(self):
        """ Return key in WIF format.

        Returns (str):
            Key in WIF format
        """
        wif_net_vers = self.m_coin_helper.WifNetVersions()

        if not wif_net_vers is None:
            wif_net_ver = wif_net_vers["main"] if not self.m_bip32_obj.IsTestNet() else wif_net_vers["test"]
            return WifEncoder.Encode(self.Raw().ToBytes(), wif_net_ver)
        else:
            return ""
