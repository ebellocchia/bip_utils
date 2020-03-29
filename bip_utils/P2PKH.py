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
from . import utils
from .base58 import Base58Encoder


class P2PKHConst:
    """ Class container for P2PKH constants. """

    # Main net address version
    MAINNET_ADDR_VER     = b"\x00"
    # Test net address version
    TESTNET_ADDR_VER     = b"\x6f"


class P2PKH:
    """ P2PKH class. It allows the Pay-to-Public-Key-Hash address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes, is_testnet = False):
        """ Get address in P2PKH format.

        Args:
            pub_key_bytes (bytes)       : public key bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """
        addr_ver = P2PKHConst.MAINNET_ADDR_VER if not is_testnet else P2PKHConst.TESTNET_ADDR_VER
        return Base58Encoder.CheckEncode(addr_ver + utils.Hash160(pub_key_bytes))
