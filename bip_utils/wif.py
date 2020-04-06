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
from .base58        import Base58Decoder, Base58Encoder
from .bip_coin_conf import BitcoinConf


class WifConst:
    """ Class container for WIF constants. """

    # Public key suffix
    PUB_KEY_SUFFIX  = b"\x01"

class WifEncoder:
    """ WIF encoder class. It provides methods for encoding to WIF format. """

    @staticmethod
    def Encode(key_bytes, net_addr_ver = BitcoinConf.WIF_NET_VER["main"], is_public = False):
        """ Encode key bytes into a WIF string.

        Args:
            key_bytes (bytes) : key bytes
            is_testnet (bool) : true if test net, false otherwise
            is_public (bool)  : true if public key, false otherwise

        Returns (string):
            WIF encoded string
        """

        key_bytes = net_addr_ver + key_bytes

        if is_public:
            key_bytes = key_bytes + WifConst.PUB_KEY_SUFFIX

        return Base58Encoder.CheckEncode(key_bytes)

class WifDecoder:
    """ WIF encoder class. It provides methods for encoding to WIF format."""

    @staticmethod
    def Decode(wif_str):
        """ Decode key bytes from a WIF string.
        RuntimeError is raised if checksum is not valid.

        Args:
            wif_str (str) : WIF string

        Returns (bytes):
            Key bytes
        """

        # Check decode string
        key_bytes = Base58Decoder.CheckDecode(wif_str)

        # Get if it's a public key from the first character of the string
        is_public = wif_str[0] == 'K' or wif_str[0] == 'L' or wif_str[0] == 'c'

        if is_public:
            return key_bytes[1:-1]
        else:
            return key_bytes[1:]
