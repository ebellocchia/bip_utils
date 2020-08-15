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
from bip_utils.bech32 import AtomBech32Encoder
from bip_utils.utils  import CryptoUtils, KeyUtils


class AtomAddr:
    """ Atom address class. It allows the Atom address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes, hrp):
        """ Get address in Atom format.

        Args:
            pub_key_bytes (bytes): Public key bytes
            hrp (str)            : HRP

        Returns:
            str: Address string

        Raises:
            ValueError: If key is not a public compressed key
        """
        if not KeyUtils.IsPublicCompressed(pub_key_bytes):
            raise ValueError("Public compressed key is required for Atom address")

        return AtomBech32Encoder.Encode(hrp, CryptoUtils.Hash160(pub_key_bytes))
