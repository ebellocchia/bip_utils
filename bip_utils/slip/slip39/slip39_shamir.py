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

"""
Module for SLIP39 Shamir's secret sharing.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
import hmac
import os
from typing import List, Sequence, Tuple

from bip_utils.slip.slip39.slip39_mnemonic import Slip39MnemonicConst
from bip_utils.utils.crypto import HmacSha256


class Slip39ShamirConst:
    """Class container for SLIP39 Shamir constants."""

    # Index of the shared secret
    SECRET_INDEX: int = 255
    # Index of the digest
    DIGEST_INDEX: int = 254
    # Digest length in bytes
    DIGEST_BYTE_LEN: int = 4
    # Rijndael irreducible polynomial (x^8 + x^4 + x^3 + x + 1)
    GF256_POLY: int = 0x11B


class Slip39Gf256:
    """
    GF(256) arithmetic class.
    Elements are bytes in polynomial representation, operations are modulo the Rijndael polynomial.
    Addition and subtraction are both XOR.
    """

    @staticmethod
    def Mul(a: int,
            b: int) -> int:
        """
        Multiply two elements.

        Args:
            a (int): First element
            b (int): Second element

        Returns:
            int: Product
        """
        res = 0
        while b:
            if b & 1:
                res ^= a
            a <<= 1
            if a & 0x100:
                a ^= Slip39ShamirConst.GF256_POLY
            b >>= 1
        return res

    @classmethod
    def Inv(cls,
            a: int) -> int:
        """
        Compute the multiplicative inverse of an element (a^254).

        Args:
            a (int): Element (shall not be zero)

        Returns:
            int: Inverse
        """
        res, base, exp = 1, a, 254
        while exp:
            if exp & 1:
                res = cls.Mul(res, base)
            base = cls.Mul(base, base)
            exp >>= 1
        return res


class Slip39Shamir:
    """
    SLIP39 Shamir class.
    It splits and recovers secrets using Shamir's secret sharing over GF(256), byte by byte.
    """

    @staticmethod
    def Interpolate(shares: Sequence[Tuple[int, bytes]],
                    x: int) -> bytes:
        """
        Compute the value at the specified index of the polynomial passing through the given shares.

        Args:
            shares (list[tuple[int, bytes]]): Shares as (index, value) pairs
            x (int)                         : Index

        Returns:
            bytes: Value at the specified index

        Raises:
            ValueError: If the shares are not valid
        """
        if len(shares) == 0:
            raise ValueError("No share specified")
        if len({share_x for share_x, _ in shares}) != len(shares):
            raise ValueError("Share indexes shall be unique")
        if len({len(share_y) for _, share_y in shares}) != 1:
            raise ValueError("Share values shall have the same length")

        for share_x, share_y in shares:
            if share_x == x:
                return share_y

        res = bytearray(len(shares[0][1]))
        for i, (xi, yi) in enumerate(shares):
            # Lagrange basis polynomial evaluated at x
            num, den = 1, 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    num = Slip39Gf256.Mul(num, x ^ xj)
                    den = Slip39Gf256.Mul(den, xi ^ xj)
            basis = Slip39Gf256.Mul(num, Slip39Gf256.Inv(den))
            for k, yik in enumerate(yi):
                res[k] ^= Slip39Gf256.Mul(yik, basis)
        return bytes(res)

    @classmethod
    def SplitSecret(cls,
                    threshold: int,
                    shares_num: int,
                    secret: bytes) -> List[Tuple[int, bytes]]:
        """
        Split a secret.

        Args:
            threshold (int) : Number of shares needed to recover the secret
            shares_num (int): Total number of shares
            secret (bytes)  : Secret

        Returns:
            list[tuple[int, bytes]]: Shares as (index, value) pairs, with indexes from 0 to shares_num - 1

        Raises:
            ValueError: If the parameters are not valid
        """
        if not 0 < threshold <= shares_num <= Slip39MnemonicConst.MAX_SHARES_NUM:
            raise ValueError(f"Invalid threshold ({threshold}) or number of shares ({shares_num})")

        if threshold == 1:
            return [(i, secret) for i in range(shares_num)]

        random_shares_num = threshold - 2
        shares = [(i, os.urandom(len(secret))) for i in range(random_shares_num)]

        random_part = os.urandom(len(secret) - Slip39ShamirConst.DIGEST_BYTE_LEN)
        digest = cls.__Digest(random_part, secret)
        base_shares = shares + [
            (Slip39ShamirConst.DIGEST_INDEX, digest + random_part),
            (Slip39ShamirConst.SECRET_INDEX, secret),
        ]

        return shares + [(i, cls.Interpolate(base_shares, i)) for i in range(random_shares_num, shares_num)]

    @classmethod
    def RecoverSecret(cls,
                      threshold: int,
                      shares: Sequence[Tuple[int, bytes]]) -> bytes:
        """
        Recover a secret.

        Args:
            threshold (int)                 : Number of shares needed to recover the secret
            shares (list[tuple[int, bytes]]): Shares as (index, value) pairs

        Returns:
            bytes: Secret

        Raises:
            ValueError: If the shares are not valid or the digest doesn't match
        """
        if threshold == 1:
            return shares[0][1]

        secret = cls.Interpolate(shares, Slip39ShamirConst.SECRET_INDEX)
        digest_share = cls.Interpolate(shares, Slip39ShamirConst.DIGEST_INDEX)
        digest = digest_share[:Slip39ShamirConst.DIGEST_BYTE_LEN]
        random_part = digest_share[Slip39ShamirConst.DIGEST_BYTE_LEN:]

        if not hmac.compare_digest(digest, cls.__Digest(random_part, secret)):
            raise ValueError("Invalid digest of the shared secret")
        return secret

    @staticmethod
    def __Digest(random_part: bytes,
                 secret: bytes) -> bytes:
        """
        Compute the digest of the shared secret.

        Args:
            random_part (bytes): Random part
            secret (bytes)     : Secret

        Returns:
            bytes: Digest
        """
        return HmacSha256.QuickDigest(random_part, secret)[:Slip39ShamirConst.DIGEST_BYTE_LEN]
