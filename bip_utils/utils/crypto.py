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
import hashlib
import hmac


class CryptoUtils:
    """ Class container for crypto utility functions. """

    @staticmethod
    def Sha256(data_bytes):
        """ Compute the SHA256 of the specified bytes.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed SHA256
        """
        return hashlib.sha256(data_bytes).digest()

    @staticmethod
    def Sha256DigestSize():
        """ Get the SHA256 digest size in bytes.

        Returns:
            int: SHA256 digest size in bytes
        """
        return hashlib.sha256().digest_size

    @staticmethod
    def HmacSha512(key_bytes, data_bytes):
        """ Compute the HMAC-SHA512 of the specified bytes with the specified key.

        Args:
            key_bytes (bytes) : Key bytes
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed HMAC-SHA512
        """
        return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()

    @staticmethod
    def Pbkdf2HmacSha512(password_bytes, salt_bytes, itr_num):
        """ Compute the PBKDF2 HMAC-SHA512 of the specified password, using the specified keys and iteration number.

        Args:
            password_bytes (bytes): Password bytes
            salt_bytes (bytes)    : Salt bytes
            itr_num (int)         : Iteration number

        Returns:
            bytes: Computed PBKDF2 HMAC-SHA512
        """
        return hashlib.pbkdf2_hmac("sha512", password_bytes, salt_bytes, itr_num)

    @staticmethod
    def Hash160(data_bytes):
        """ Compute the Bitcoin Hash-160 of the specified bytes.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed Hash-160
        """
        return hashlib.new("ripemd160", CryptoUtils.Sha256(data_bytes)).digest()
