# Copyright (c) 2021 Emanuele Bellocchia
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
from enum import Enum, auto, unique
from bip_utils.bech32 import AvaxChainTypes, AvaxBech32Encoder
from bip_utils.utils import CryptoUtils, KeyUtils


class AvaxXChainAddr:
    """ Avax X-Chain address class. It allows the Avax X-Chain address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes: bytes) -> str:
        """ Get address in Atom format.

        Args:
            pub_key_bytes (bytes) : Public key bytes

        Returns:
            str: Address string

        Raises:
            ValueError: If key is not a public compressed key
        """
        if not KeyUtils.IsPublicCompressed(pub_key_bytes):
            raise ValueError("Public compressed key is required for Avax address")

        return AvaxBech32Encoder.Encode(CryptoUtils.Hash160(pub_key_bytes), AvaxChainTypes.AVAX_X_CHAIN)


class AvaxPChainAddr:
    """ Avax P-Chain address class. It allows the Avax P-Chain address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes: bytes) -> str:
        """ Get address in Atom format.

        Args:
            pub_key_bytes (bytes) : Public key bytes

        Returns:
            str: Address string

        Raises:
            ValueError: If key is not a public compressed key
        """
        if not KeyUtils.IsPublicCompressed(pub_key_bytes):
            raise ValueError("Public compressed key is required for Avax address")

        return AvaxBech32Encoder.Encode(CryptoUtils.Hash160(pub_key_bytes), AvaxChainTypes.AVAX_P_CHAIN)
