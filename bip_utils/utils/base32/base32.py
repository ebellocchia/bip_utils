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
import base64
from typing import Optional, Union
from bip_utils.utils.misc.algo import AlgoUtils


class Base32Const:
    """ Class container for Base32 constants. """

    # Alphabet
    ALPHABET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    # Padding character
    PADDING_CHAR: str = "="


class Base32Encoder:
    """ Base32 encoder class. It provides methods for encoding to Base32 format. """

    @staticmethod
    def Encode(data: Union[bytes, str],
               custom_alphabet: Optional[str] = None) -> str:
        """ Encode to base32.

        Args:
            data (str or bytes)            : Data
            custom_alphabet (str, optional): Custom alphabet string

        Returns:
            str: Encoded string
        """
        b32_enc = AlgoUtils.Decode(base64.b32encode(AlgoUtils.Encode(data)))
        if custom_alphabet is not None:
            b32_enc = b32_enc.translate(str.maketrans(Base32Const.ALPHABET, custom_alphabet))

        return b32_enc

    @staticmethod
    def EncodeNoPadding(data: Union[bytes, str],
                        custom_alphabet: Optional[str] = None) -> str:
        """ Encode to base32 by removing the final padding.

        Args:
            data (str or bytes)            : Data
            custom_alphabet (str, optional): Custom alphabet string

        Returns:
            str: Encoded string
        """
        return Base32Encoder.Encode(data, custom_alphabet).rstrip(Base32Const.PADDING_CHAR)
