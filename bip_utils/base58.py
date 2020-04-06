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
from . import utils


class Base58Const:
    """ Class container for Base58 constants. """

    # Base58 alphabet
    ALPHABET          =  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Base58 alphabet bytes
    ALPHABET_BYTES    = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Base58 radix
    RADIX             = 58
    # Checksum length in bytes
    CHECKSUM_BYTE_LEN = 4


class Base58Utils:
    """ Class container for Base58 utility functions. """

    @staticmethod
    def ComputeChecksum(data_bytes):
        """ Compute Base58 checksum.

        Args:
            data_bytes (bytes) : data bytes

        Returns (bytes):
            Computed checksum
        """

        return utils.Sha256(utils.Sha256(data_bytes))[:Base58Const.CHECKSUM_BYTE_LEN]


class Base58ChecksumError(Exception):
    """ Exception in case of checksum error. """

    pass


class Base58Encoder:
    """ Base58 encoder class. It provides methods for encoding and checksum encoding to Base58 format. """

    @staticmethod
    def Encode(data_bytes):
        """ Encode bytes into a Base58 string.

        Args:
            data_bytes (bytes) : data bytes

        Returns (string):
            Base58 encoded string
        """

        enc = ""

        # Convert bytes to integer
        val = utils.BytesToInteger(data_bytes)

        # Algorithm implementation
        while val > 0:
            val, mod = divmod(val, Base58Const.RADIX)
            enc = Base58Const.ALPHABET[mod] + enc

        # Get number of leading zeros
        n = len(data_bytes) - len(data_bytes.lstrip(b"\0"))
        # Add padding
        return (Base58Const.ALPHABET[0] * n) + enc

    @staticmethod
    def CheckEncode(data_bytes):
        """Encode bytes into Base58 string with checksum.

        Args:
            data_bytes (bytes) : data bytes

        Returns (string):
            Base58 encoded string with checksum
        """

        # Append checksum and encode all together
        return Base58Encoder.Encode(data_bytes + Base58Utils.ComputeChecksum(data_bytes))


class Base58Decoder:
    """ Base58 decoder class. It provides methods for decoding and checksum decoding Base58 format. """

    @staticmethod
    def Decode(data_str):
        """ Decode bytes from a Base58 string.
        ValueError is raised if the string is not a valid Base58 format.

        Args:
            data_str (str) : data string

        Returns (bytes):
            Base58 decoded bytes
        """

        # Convert string to integer
        val = 0
        for (i, c) in enumerate(data_str[::-1]):
            val += Base58Const.ALPHABET.index(c) * (Base58Const.RADIX ** i)

        dec = bytearray()
        while val > 0:
            val, mod = divmod(val, 256)
            dec.append(mod)

        # Get padding length
        pad_len = len(data_str) - len(data_str.lstrip(Base58Const.ALPHABET[0]))
        # Add padding
        return (b"\0" * pad_len) + bytes(dec[::-1])

    @staticmethod
    def CheckDecode(data_str):
        """Decode bytes from a Base58 string with checksum.
        ValueError is raised if the string is not a valid Base58 format.
        Base58ChecksumError is raised if checksum is not valid.

        Args:
            data_str (str) : data string

        Returns (bytes):
            Base58 decoded bytes (checksum removed)
        """

        # Decode string
        dec_bytes = Base58Decoder.Decode(data_str)
        # Get data and checksum bytes
        data_bytes, checksum_bytes = dec_bytes[:-Base58Const.CHECKSUM_BYTE_LEN], dec_bytes[-Base58Const.CHECKSUM_BYTE_LEN:]

        # Compute checksum
        comp_checksum = Base58Utils.ComputeChecksum(data_bytes)

        # Verify checksum
        if checksum_bytes != comp_checksum:
            raise Base58ChecksumError("Invalid checksum (expected %s, got %s)" % (comp_checksum, checksum_bytes))

        return data_bytes
