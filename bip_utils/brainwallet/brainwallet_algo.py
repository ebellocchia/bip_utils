# Copyright (c) 2023 Emanuele Bellocchia
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

"""Module for implementing algorithms for brainwallet generation."""

# Imports
from enum import Enum, auto, unique
from typing import Any

from bip_utils.brainwallet.ibrainwallet_algo import IBrainwalletAlgo
from bip_utils.utils.crypto import DoubleSha256, Pbkdf2HmacSha512, Scrypt, Sha256


@unique
class BrainwalletAlgos(Enum):
    """Enum for brainwallet algorithms."""

    SHA256 = auto()
    DOUBLE_SHA256 = auto()
    PBKDF2_HMAC_SHA512 = auto()
    SCRYPT = auto()


class BrainwalletAlgoConst:
    """Class container for brainwallet algorithm constants."""

    PBKDF2_HMAC_SHA512_KEY_LEN: int = 32
    PBKDF2_HMAC_SHA512_DEF_ITR_NUM: int = 2 * 1024 * 1024
    SCRYPT_KEY_LEN: int = 32
    SCRYPT_DEF_N: int = 128 * 1024
    SCRYPT_DEF_P: int = 8
    SCRYPT_DEF_R: int = 8


class BrainwalletAlgoSha256(IBrainwalletAlgo):
    """Compute the private key from passphrase using SHA256 algorithm."""

    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        """
        Compute the private key from the specified passphrase.

        Args:
            passphrase (str): Passphrase
            **kwargs        : Not used

        Returns:
            bytes: Private key bytes
        """
        return Sha256.QuickDigest(passphrase)


class BrainwalletAlgoDoubleSha256(IBrainwalletAlgo):
    """Compute the private key from passphrase using double SHA256 algorithm."""

    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        """
        Compute the private key from the specified passphrase.

        Args:
            passphrase (str): Passphrase
            **kwargs        : Not used

        Returns:
            bytes: Private key bytes
        """
        return DoubleSha256.QuickDigest(passphrase)


class BrainwalletAlgoPbkdf2HmacSha512(IBrainwalletAlgo):
    """Compute the private key from passphrase using PBKDF2 HMAC-SHA512 algorithm."""

    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        """
        Compute the private key from the specified passphrase.

        Args:
            passphrase (str): Passphrase

        Other Parameters:
            salt (str)   : Salt for PBKDF2 algorithm (default: empty)
            itr_num (int): Number of iteration for PBKDF2 algorithm (default: 2097152)

        Returns:
            bytes: Private key bytes
        """
        salt = kwargs.get("salt", "")
        itr_num = kwargs.get("itr_num", BrainwalletAlgoConst.PBKDF2_HMAC_SHA512_DEF_ITR_NUM)

        return Pbkdf2HmacSha512.DeriveKey(
            passphrase,
            salt,
            itr_num=itr_num,
            dklen=BrainwalletAlgoConst.PBKDF2_HMAC_SHA512_KEY_LEN
        )


class BrainwalletAlgoScrypt(IBrainwalletAlgo):
    """Compute the private key from passphrase using Scrypt algorithm."""

    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        """
        Compute the private key from the specified passphrase.

        Args:
            passphrase (str): Passphrase

        Other Parameters:
            salt (str): Salt for Scrypt algorithm (default: empty)
            n (int)   : CPU/Memory cost parameter for Scrypt algorithm (default: 131072)
            r (int)   : Block size parameter for Scrypt algorithm (default: 8)
            p (int)   : Parallelization parameter for Scrypt algorithm (default: 8)

        Returns:
            bytes: Private key bytes
        """
        salt = kwargs.get("salt", "")
        n = kwargs.get("n", BrainwalletAlgoConst.SCRYPT_DEF_N)
        r = kwargs.get("r", BrainwalletAlgoConst.SCRYPT_DEF_R)
        p = kwargs.get("p", BrainwalletAlgoConst.SCRYPT_DEF_P)

        return Scrypt.DeriveKey(
            passphrase,
            salt,
            key_len=BrainwalletAlgoConst.SCRYPT_KEY_LEN,
            n=n,
            r=r,
            p=p
        )
