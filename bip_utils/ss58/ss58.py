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
from typing import Tuple
from bip_utils.ss58.ss58_ex import SS58ChecksumError
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.utils import CryptoUtils


class SS58Const:
    """ Class container for SS58 constants. """

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 2
    # Data length in bytes
    DATA_BYTE_LEN: int = 32
    # Version length in bytes
    VERSION_BYTE_LEN: int = 1
    # Checksum prefix
    CHECKSUM_PREFIX: bytes = b"SS58PRE"


class SS58Utils:
    """ Class container for SS58 utility functions. """

    @staticmethod
    def ComputeChecksum(data_bytes: bytes) -> bytes:
        """ Compute SS58 checksum.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed checksum
        """
        return CryptoUtils.Blake2b(SS58Const.CHECKSUM_PREFIX + data_bytes)[:SS58Const.CHECKSUM_BYTE_LEN]


class SS58Encoder:
    """ SS58 encoder class. It provides methods for encoding to SS58 format. """

    @staticmethod
    def Encode(data_bytes: bytes,
               version: bytes) -> str:
        """ Encode bytes into a SS58 string.

        Args:
            data_bytes (bytes): Data bytes (32-byte length)
            version (bytes)   : Version byte (1-byte length)

        Returns:
            str: SS58 encoded string

        Raises:
            ValueError: If the parameters are not valid
        """

        # Check lengths
        if len(data_bytes) != SS58Const.DATA_BYTE_LEN:
            raise ValueError("Invalid data length (%d)" % len(data_bytes))
        if len(version) != SS58Const.VERSION_BYTE_LEN:
            raise ValueError("Invalid version length (%d)" % len(version))

        # Get payload
        payload = version + data_bytes
        # Compute checksum
        checksum = SS58Utils.ComputeChecksum(payload)
        # Encode
        return Base58Encoder.Encode(payload + checksum)


class SS58Decoder:
    """ SS58 decoder class. It provides methods for decoding SS58 format. """

    @staticmethod
    def Decode(data_str: str) -> Tuple[bytes, bytes]:
        """ Decode bytes from a SS58 string.

        Args:
            data_str (string): Data string

        Returns:
            tuple: version and data bytes

        Raises:
            SS58ChecksumError: If checksum is not valid
            ValueError: If the string is not a valid Base58 format
        """

        # Decode string
        dec_bytes = Base58Decoder.Decode(data_str)
        # Get back all the parts
        version = dec_bytes[:SS58Const.VERSION_BYTE_LEN]
        data_bytes = dec_bytes[SS58Const.VERSION_BYTE_LEN:-SS58Const.CHECKSUM_BYTE_LEN]
        checksum_bytes = dec_bytes[-SS58Const.CHECKSUM_BYTE_LEN:]

        # Check lengths
        if len(data_bytes) != SS58Const.DATA_BYTE_LEN:
            raise ValueError("Invalid data length (%d)" % len(data_bytes))

        # Compute checksum
        comp_checksum = SS58Utils.ComputeChecksum(version + data_bytes)

        # Verify checksum
        if checksum_bytes != comp_checksum:
            raise SS58ChecksumError("Invalid checksum (expected %r, got %r)" % (comp_checksum, checksum_bytes))

        return version, data_bytes
