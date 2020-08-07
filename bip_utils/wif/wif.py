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
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.conf   import BitcoinConf
from bip_utils.utils  import ConvUtils, KeyUtils


class WifConst:
    """ Class container for WIF constants. """

    # Suffix to be added if the private key correspond to a compressed public key
    COMPR_PUB_KEY_SUFFIX = b"\x01"


class WifEncoder:
    """ WIF encoder class. It provides methods for encoding to WIF format. """

    @staticmethod
    def Encode(key_bytes, compr_pub_key = True, net_addr_ver = BitcoinConf.WIF_NET_VER.Main()):
        """ Encode key bytes into a WIF string.

        Args:
            key_bytes (bytes)             : Key bytes
            compr_pub_key (bool)          : True if private key corresponds to a compressed public key, false otherwise
            net_addr_ver (bytes, optional): Net address version, default is Bitcoin main network

        Returns:
            str: WIF encoded string

        Raises:
            ValueError: If the key is not valid
        """

        # Check key
        if not KeyUtils.IsPrivate(key_bytes):
            raise ValueError("Invalid key (%s)" % ConvUtils.BytesToHexString(key_bytes))

        # Add suffix if correspond to a compressed public key
        if compr_pub_key:
            key_bytes += WifConst.COMPR_PUB_KEY_SUFFIX

        # Add net address version
        key_bytes = net_addr_ver + key_bytes

        # Encode key
        return Base58Encoder.CheckEncode(key_bytes)

class WifDecoder:
    """ WIF encoder class. It provides methods for encoding to WIF format."""

    @staticmethod
    def Decode(wif_str, net_addr_ver = BitcoinConf.WIF_NET_VER.Main()):
        """ Decode key bytes from a WIF string.

        Args:
            wif_str (str)                 : WIF string
            net_addr_ver (bytes, optional): Net address version, default is Bitcoin main network

        Returns:
            bytes: Key bytes

        Raises:
            Base58ChecksumError: If the base58 checksum is not valid
            ValueError: If the resulting key is not valid
        """

        # Decode string
        key_bytes = Base58Decoder.CheckDecode(wif_str)

        # Check net version
        if key_bytes[0] != ord(net_addr_ver):
            raise ValueError("Invalid net version (expected %x, got %x)" % (ord(net_addr_ver), key_bytes[0]))

        # Remove net version
        key_bytes = key_bytes[1:]

        # Remove suffix if correspond to a compressed public key
        if KeyUtils.IsPrivate(key_bytes[:-1]):
            # Check the compressed public key suffix
            if key_bytes[-1] != ord(WifConst.COMPR_PUB_KEY_SUFFIX):
                raise ValueError("Invalid compressed public key suffix (expected %x, got %x)" % (ord(WifConst.COMPR_PUB_KEY_SUFFIX), key_bytes[-1]))
            # Remove it
            key_bytes = key_bytes[:-1]

        # Check if valid
        if not KeyUtils.IsValid(key_bytes):
            raise ValueError("Invalid decoded key (%s)" % ConvUtils.BytesToHexString(key_bytes))

        return key_bytes
