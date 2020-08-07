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


class KeyUtilsConst:
    """ Class container for key helper constants. """

    # Private key length
    PRIV_KEY_LEN         = 32
    # Public uncompressed key length
    PUB_KEY_UNCOMPR_LEN  = 64
    # Public compressed key length
    PUB_KEY_COMPR_LEN    = 33
    # Public compressed key prefix (0x02, 0x03)
    PUB_KEY_COMPR_PREFIX = (2, 3)


class KeyUtils:
    """ Key helper class. It provides methods for checking formats of ECDSA keys. """

    @staticmethod
    def IsPrivate(key_bytes):
        """ Get if the specified key is private.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bool: True if private, false otherwise
        """
        return len(key_bytes) == KeyUtilsConst.PRIV_KEY_LEN

    @staticmethod
    def IsPublicUncompressed(key_bytes):
        """ Get if the specified key is public uncompressed (first version byte not considered).

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bool: True if public uncompressed, false otherwise
        """
        return len(key_bytes) == KeyUtilsConst.PUB_KEY_UNCOMPR_LEN

    @staticmethod
    def IsPublicCompressed(key_bytes):
        """ Get if the specified key is public compressed.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bool: True if public compressed, false otherwise
        """
        return len(key_bytes) == KeyUtilsConst.PUB_KEY_COMPR_LEN and key_bytes[0] in KeyUtilsConst.PUB_KEY_COMPR_PREFIX

    @staticmethod
    def IsValid(key_bytes):
        """ Get if the specified key is valid.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bool: True if private or public compressed/decompressed, false otherwise
        """
        return KeyUtils.IsPrivate(key_bytes)            or \
               KeyUtils.IsPublicUncompressed(key_bytes) or \
               KeyUtils.IsPublicCompressed(key_bytes)
