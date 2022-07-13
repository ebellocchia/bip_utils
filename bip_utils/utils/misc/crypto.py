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

"""Module with some cryptography utility functions."""

# Imports
import binascii
import hashlib
import hmac
from typing import Optional, Union
import crcmod.predefined
from Crypto.Hash import keccak, RIPEMD160, SHA512, SHA3_256
from Crypto.Protocol.KDF import PBKDF2, scrypt
from bip_utils.utils.misc.algo import AlgoUtils


HASHLIB_USE_PBKDF2_SHA512: bool = hasattr(hashlib, "pbkdf2_hmac")   # For future changes
HASHLIB_USE_SHA3_256: bool = "sha3_256" in hashlib.algorithms_available
HASHLIB_USE_SHA512_256: bool = "sha512_256" in hashlib.algorithms_available


class CryptoUtils:
    """Class container for crypto utility functions."""

    @staticmethod
    def Blake2b(data: Union[bytes, str],
                digest_size: int = 64,
                key: bytes = b"",
                salt: bytes = b"") -> bytes:
        """
        Compute the Blake2b of the specified bytes.

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
        """
        Compute the Kekkak256 of the specified bytes.

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
        """
        Compute the SHA256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA256
        """
        return hashlib.sha256(AlgoUtils.Encode(data)).digest()

    @staticmethod
    def DoubleSha256(data: Union[bytes, str]) -> bytes:
        """
        Compute the double SHA256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA256
        """
        return CryptoUtils.Sha256(CryptoUtils.Sha256(data))

    @staticmethod
    def Sha256DigestSize() -> int:
        """
        Get the SHA256 digest size in bytes.

        Returns:
            int: SHA256 digest size in bytes
        """
        return hashlib.sha256().digest_size

    @staticmethod
    def Sha3_256(data: Union[bytes, str]) -> bytes:
        """
        Compute the SHA3-256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA3-256
        """
        if HASHLIB_USE_SHA3_256:
            return hashlib.new("sha3_256", AlgoUtils.Encode(data)).digest()
        # Use Cryptodome if not implemented in hashlib
        h = SHA3_256.new()
        h.update(AlgoUtils.Encode(data))
        return h.digest()

    @staticmethod
    def Sha512_256(data: Union[bytes, str]) -> bytes:
        """
        Compute the SHA512/256 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed SHA512/256
        """
        if HASHLIB_USE_SHA512_256:
            return hashlib.new("sha512_256", AlgoUtils.Encode(data)).digest()
        # Use Cryptodome if not implemented in hashlib
        h = SHA512.new(truncate="256")
        h.update(AlgoUtils.Encode(data))
        return h.digest()

    @staticmethod
    def HmacSha512(key: Union[bytes, str],
                   data: Union[bytes, str]) -> bytes:
        """
        Compute the HMAC-SHA512 of the specified bytes with the specified key.

        Args:
            key (str or bytes) : Key
            data (str or bytes): Data

        Returns:
            bytes: Computed HMAC-SHA512
        """
        # Use digest if available
        if hasattr(hmac, "digest"):
            return hmac.digest(AlgoUtils.Encode(key), AlgoUtils.Encode(data), "sha512")
        return hmac.new(AlgoUtils.Encode(key), AlgoUtils.Encode(data), hashlib.sha512).digest()

    @staticmethod
    def HmacSha256(key: Union[bytes, str],
                   data: Union[bytes, str]) -> bytes:
        """
        Compute the HMAC-SHA256 of the specified bytes with the specified key.

        Args:
            key (str or bytes) : Key
            data (str or bytes): Data

        Returns:
            bytes: Computed HMAC-SHA256
        """
        # Use digest if available
        if hasattr(hmac, "digest"):
            return hmac.digest(AlgoUtils.Encode(key), AlgoUtils.Encode(data), "sha256")
        return hmac.new(AlgoUtils.Encode(key), AlgoUtils.Encode(data), hashlib.sha256).digest()

    @staticmethod
    def Pbkdf2HmacSha512(password: Union[bytes, str],
                         salt: Union[bytes, str],
                         itr_num: int,
                         dklen: Optional[int] = None) -> bytes:
        """
        Compute the PBKDF2 HMAC-SHA512 of the specified password, using the specified keys and iteration number.

        Args:
            password (str or bytes): Password
            salt (str or bytes)    : Salt
            itr_num (int)          : Iteration number
            dklen (int, optional)  : Length of the derived key (default: SHA-512 output length)

        Returns:
            bytes: Computed PBKDF2 HMAC-SHA512
        """
        if HASHLIB_USE_PBKDF2_SHA512:
            return hashlib.pbkdf2_hmac("sha512", AlgoUtils.Encode(password), AlgoUtils.Encode(salt), itr_num, dklen)
        # Use Cryptodome if not implemented in hashlib
        return PBKDF2(AlgoUtils.Encode(password),   # type: ignore
                      AlgoUtils.Encode(salt),
                      dklen or SHA512.digest_size,
                      count=itr_num,
                      hmac_hash_module=SHA512)

    @staticmethod
    def Scrypt(password: Union[bytes, str],
               salt: Union[bytes, str],
               key_len: int,
               n: int,
               r: int,
               p: int) -> bytes:
        """
        Compute the scrypt of the specified password, using the specified parameters.

        Args:
            password (str or bytes): Password
            salt (str or bytes)    : Salt
            key_len (int)          : Length of the derived key
            n (int)                : CPU/Memory cost parameter
            r (int)                : Block size parameter
            p (int)                : Parallelization parameter

        Returns:
            bytes: Computed scrypt
        """

        # Type for password and salt should be Union[bytes, str] in pycryptodome but it's only str,
        # so we ignore the mypy warning
        return scrypt(AlgoUtils.Encode(password),   # type: ignore
                      AlgoUtils.Encode(salt),       # type: ignore
                      key_len=key_len,
                      N=n,
                      r=r,
                      p=p)

    @staticmethod
    def Ripemd160(data: Union[bytes, str]) -> bytes:
        """
        Compute the RIPEMD-160 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed RIPEMD-160
        """
        h = RIPEMD160.new()
        h.update(AlgoUtils.Encode(data))
        return h.digest()

    @staticmethod
    def Ripemd160DigestSize() -> int:
        """
        Get the RIPEMD-160 size in bytes.

        Returns:
            int: RIPEMD-160 size in bytes
        """
        return RIPEMD160.digest_size

    @staticmethod
    def Hash160(data: Union[bytes, str]) -> bytes:
        """
        Compute the Bitcoin Hash-160 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed Hash-160
        """
        return CryptoUtils.Ripemd160(CryptoUtils.Sha256(data))

    @staticmethod
    def Hash160DigestSize() -> int:
        """
        Get the Hash-160 size in bytes.

        Returns:
            int: Hash-160 size in bytes
        """
        return CryptoUtils.Ripemd160DigestSize()

    @staticmethod
    def Crc32(data: Union[bytes, str]) -> int:
        """
        Compute the CRC32 of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            int: Computed CRC32
        """
        return binascii.crc32(AlgoUtils.Encode(data))

    @staticmethod
    def XModemCrc(data: Union[bytes, str]) -> bytes:
        """
        Compute the XMODEM-CRC of the specified bytes.

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed XMODEM-CRC
        """
        crc_fct = crcmod.predefined.Crc("xmodem")
        crc_fct.update(AlgoUtils.Encode(data))
        return crc_fct.digest()
