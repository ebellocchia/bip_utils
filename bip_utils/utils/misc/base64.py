# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module with helper class for Base64."""

# Imports
import base64
import binascii
from typing import Union

from bip_utils.utils.misc.algo import AlgoUtils


class Base64Decoder:
    """
    Base64 decoder class.
    It provides methods for decoding to Base64 format.
    """

    @staticmethod
    def Decode(data: str) -> bytes:
        """
        Decode from Base64.

        Args:
            data (str): Data

        Returns:
            bytes: Decoded bytes

        Raises:
            ValueError: If the Base64 string is not valid
        """
        try:
            return base64.b64decode(data)
        except binascii.Error as ex:
            raise ValueError("Invalid Base64 string") from ex


class Base64Encoder:
    """
    Base64 encoder class.
    It provides methods for encoding to Base64 format.
    """

    @staticmethod
    def Encode(data: Union[bytes, str]) -> bytes:
        """
        Encode to Base64.

        Args:
            data (str or bytes): Data

        Returns:
            str: Encoded string
        """
        return base64.b64encode(AlgoUtils.Encode(data))
