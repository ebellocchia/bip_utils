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
from typing import Union
from bip_utils.utils.algo import AlgoUtils


class Base32:
    """ Class container for Base32 deconding/encoding. """

    @staticmethod
    def Encode(data: Union[bytes, str]) -> bytes:
        """ Encode to Base32.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Encoded bytes
        """
        return base64.b32encode(AlgoUtils.Encode(data))

    @staticmethod
    def Decode(data: Union[bytes, str]) -> bytes:
        """ Decode from Base32.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Decoded bytes
        """
        return base64.b32decode(data)
