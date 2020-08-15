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
from bip_utils.addr.eth_addr import EthAddr
from bip_utils.base58        import Base58Encoder


class TrxAddrConst:
    """ Class container for Tron address constants. """

    # Prefix
    PREFIX = "41"


class TrxAddr:
    """ Tron address class. It allows the Tron address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes):
        """ Get address in Tron format.

        Args:
            pub_key_bytes (bytes): Public key bytes

        Returns:
            str: Address string

        Raised:
            ValueError: If the key is not a public uncompressed key
        """

        # Get address in Ethereum format (remove "0x" at the beginning)
        addr = EthAddr.ToAddress(pub_key_bytes)[2:]

        # Add prefix and encode
        return Base58Encoder.CheckEncode(binascii.unhexlify(TrxAddrConst.PREFIX + addr))
