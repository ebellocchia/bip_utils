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
from bip_utils.bech32 import AtomBech32Encoder


class OneAddrConst:
    """ Class container for Harmony One address constants. """

    # Huma-readable part
    HRP: str = "one"


class OneAddr:
    """ Harmony One address class. It allows the Harmony One address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes: bytes) -> str:
        """ Get address in Harmony One format.

        Args:
            pub_key_bytes (bytes): Public key bytes

        Returns:
            str: Address string

        Raises:
            ValueError: If key is not a public uncompressed key
        """

        # Get address in Ethereum format (remove "0x" at the beginning)
        addr = EthAddr.ToAddress(pub_key_bytes)[2:]

        # Encode in Atom format
        return AtomBech32Encoder.Encode(OneAddrConst.HRP, binascii.unhexlify(addr))
