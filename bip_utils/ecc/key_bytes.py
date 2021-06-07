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
from bip_utils.utils.conversion import ConvUtils


class KeyBytes:
    """ Key bytes class. It allows to get key bytes in different formats. """

    def __init__(self,
                 key_bytes: bytes) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes): Key bytes
        """
        self.m_key_bytes = key_bytes

    def ToBytes(self) -> bytes:
        """ Get key bytes.

        Returns:
            bytes: Key bytes
        """
        return self.m_key_bytes

    def ToHex(self) -> str:
        """ Get key bytes in hex format.

        Returns:
            str: Key bytes in hex format
        """
        return ConvUtils.BytesToHexString(self.m_key_bytes)

    def __bytes__(self) -> bytes:
        """ Get key bytes.

        Returns:
            bytes: Key bytes
        """
        return self.ToBytes()

    def __str__(self) -> str:
        """ Get key bytes as string.

        Returns:
            str: Key bytes as string
        """
        return self.ToHex()
