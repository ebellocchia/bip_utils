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
import hashlib
import hmac
import crcmod.predefined
from Crypto.Hash import keccak
from Crypto.Hash import SHA512
from typing import Union
from bip_utils.utils.algo import AlgoUtils


class CryptoUtils:
    """ Class container for crypto utility functions. """

    @staticmethod
    def Blake2b(data: Union[bytes, str],
                digest_size: int = 64,
                key: bytes = b"",
                salt: bytes = b"") -> bytes:
        """ Compute the Blake2b of the specified bytes.

        Args:
            data (str or bytes)        : Data
            digest_size (int, optional): Digest size (default: 64)
            key (bytes, optional)      : Key bytes (default: empty)
            salt (bytes, optional)     : Salt bytes (default: empty)

        Returns:
            bytes: Computed Blake2b
        """
        return hashlib.blake2b(AlgoUtils.Encode(data),
                               digest_size=digest_size,
                               key=key,
                               salt=salt).digest()

    @staticmethod
    def Kekkak256(data: Union[bytes, str]) -> bytes:
        """ Compute the Kekkak256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed Kekkak256
        """
        h = keccak.new(digest_bits=256)
        h.update(AlgoUtils.Encode(data))
        return h.digest()

    @staticmethod
    def Sha256(data: Union[bytes, str]) -> bytes:
        """ Compute the SHA256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA256
        """
        return hashlib.sha256(AlgoUtils.Encode(data)).digest()

    @staticmethod
    def Sha256DigestSize() -> int:
        """ Get the SHA256 digest size in bytes.

        Returns:
            int: SHA256 digest size in bytes
        """
        return hashlib.sha256().digest_size

    @staticmethod
    def Sha512_256(data: Union[bytes, str]) -> bytes:
        """ Compute the SHA512/256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA512/256
        """
        h = SHA512.new(truncate="256")
        h.update(AlgoUtils.Encode(data))
        return h.digest()

    @staticmethod
    def HmacSha512(key: Union[bytes, str],
                   data: Union[bytes, str]) -> bytes:
        """ Compute the HMAC-SHA512 of the specified bytes with the specified key.

        Args:
            key (str or bytes) : Key
            data (str or bytes): Data

        Returns:
            bytes: Computed HMAC-SHA512
        """
        return hmac.new(AlgoUtils.Encode(key), AlgoUtils.Encode(data), hashlib.sha512).digest()

    @staticmethod
    def Pbkdf2HmacSha512(password: Union[bytes, str],
                         salt: Union[bytes, str],
                         itr_num: int) -> bytes:
        """ Compute the PBKDF2 HMAC-SHA512 of the specified password, using the specified keys and iteration number.

        Args:
            password (str or bytes): Password
            salt (str or bytes)    : Salt
            itr_num (int)          : Iteration number

        Returns:
            bytes: Computed PBKDF2 HMAC-SHA512
        """
        return hashlib.pbkdf2_hmac("sha512", AlgoUtils.Encode(password), AlgoUtils.Encode(salt), itr_num)

    @staticmethod
    def Hash160(data: Union[bytes, str]) -> bytes:
        """ Compute the Bitcoin Hash-160 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed Hash-160
        """
        return hashlib.new("ripemd160", CryptoUtils.Sha256(data)).digest()

    @staticmethod
    def XModemCrc(data: Union[bytes, str]) -> bytes:
        """ Compute the XMODEM-CRC of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed XMODEM-CRC
        """
        crc_fct = crcmod.predefined.Crc("xmodem")
        crc_fct.update(AlgoUtils.Encode(data))
        return crc_fct.digest()
