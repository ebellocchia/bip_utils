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

"""Module for Monero Polyseed mnemonic utility classes."""

# Imports
from dataclasses import dataclass
from typing import List

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedMnemonicConst,
)


@dataclass
class MoneroPolyseedDecodedData:
    """Dataclass holding decoded Polyseed data."""

    secret: bytes
    birthday: int
    features: int
    checksum: int

    @property
    def birthday_timestamp(self) -> int:
        """Decode birthday to Unix timestamp."""
        return MoneroPolyseedMnemonicConst.EPOCH + self.birthday * MoneroPolyseedMnemonicConst.TIME_STEP

    @property
    def is_encrypted(self) -> bool:
        """Get if the seed is encrypted."""
        return (self.features & MoneroPolyseedMnemonicConst.ENCRYPTED_MASK) != 0

    @property
    def user_features(self) -> int:
        """Get user feature flags (3 bits)."""
        return self.features & MoneroPolyseedMnemonicConst.USER_FEATURES_MASK


class MoneroPolyseedGf:
    """GF(2048) arithmetic for Polyseed."""

    @staticmethod
    def ElemMul2(x: int) -> int:
        """
        Multiply element by 2 in GF(2048).

        Args:
            x (int): GF(2048) element

        Returns:
            int: Result of multiplication by 2
        """
        if x < 1024:
            return 2 * x
        return MoneroPolyseedMnemonicConst.MUL2_TABLE[x % 8] + 16 * ((x - 1024) // 8)

    @staticmethod
    def PolyEval(coeffs: List[int]) -> int:
        """
        Evaluate polynomial at x=2 using Horner's method in GF(2048).

        Args:
            coeffs (list[int]): Polynomial coefficients (16 elements)

        Returns:
            int: Evaluation result
        """
        result = coeffs[MoneroPolyseedMnemonicConst.NUM_WORDS - 1]
        for i in range(MoneroPolyseedMnemonicConst.NUM_WORDS - 2, -1, -1):
            result = MoneroPolyseedGf.ElemMul2(result) ^ coeffs[i]
        return result

    @staticmethod
    def PolyEncode(coeffs: List[int]) -> List[int]:
        """
        Calculate checksum and set coeffs[0].

        Args:
            coeffs (list[int]): Polynomial coefficients (16 elements), coeffs[0] should be 0

        Returns:
            list[int]: Coefficients with checksum set at index 0
        """
        coeffs[0] = MoneroPolyseedGf.PolyEval(coeffs)
        return coeffs

    @staticmethod
    def PolyCheck(coeffs: List[int]) -> bool:
        """
        Verify polynomial checksum (evaluation should be 0).

        Args:
            coeffs (list[int]): Polynomial coefficients (16 elements)

        Returns:
            bool: True if checksum is valid
        """
        return MoneroPolyseedGf.PolyEval(coeffs) == 0


class MoneroPolyseedMnemonicUtils:
    """Utility functions for Monero Polyseed mnemonic."""

    @staticmethod
    def BirthdayEncode(timestamp: int) -> int:
        """
        Encode a Unix timestamp to a 10-bit birthday value.

        Args:
            timestamp (int): Unix timestamp

        Returns:
            int: Encoded birthday (0-1023)
        """
        if timestamp < MoneroPolyseedMnemonicConst.EPOCH:
            return 0
        return ((timestamp - MoneroPolyseedMnemonicConst.EPOCH)
                // MoneroPolyseedMnemonicConst.TIME_STEP) & MoneroPolyseedMnemonicConst.DATE_MASK

    @staticmethod
    def BirthdayDecode(birthday: int) -> int:
        """
        Decode a 10-bit birthday value to a Unix timestamp.

        Args:
            birthday (int): Encoded birthday (0-1023)

        Returns:
            int: Unix timestamp
        """
        return MoneroPolyseedMnemonicConst.EPOCH + birthday * MoneroPolyseedMnemonicConst.TIME_STEP

    @staticmethod
    def DataToPoly(data: MoneroPolyseedDecodedData) -> List[int]:
        """
        Convert decoded data to 16 polynomial coefficients.
        Faithful port of polyseed_data_to_poly from gf.c.

        Args:
            data (MoneroPolyseedDecodedData): Decoded polyseed data

        Returns:
            list[int]: 16 polynomial coefficients
        """
        extra_val = (data.features << MoneroPolyseedMnemonicConst.DATE_BITS) | data.birthday
        extra_bits = MoneroPolyseedMnemonicConst.FEATURE_BITS + MoneroPolyseedMnemonicConst.DATE_BITS

        word_bits = 0
        word_val = 0

        secret_idx = 0
        secret_val = data.secret[secret_idx]
        secret_bits = 8
        seed_rem_bits = MoneroPolyseedMnemonicConst.SECRET_BITS - 8

        coeffs = [0] * MoneroPolyseedMnemonicConst.NUM_WORDS

        for i in range(MoneroPolyseedMnemonicConst.DATA_WORDS):
            while word_bits < MoneroPolyseedMnemonicConst.SHARE_BITS:
                if secret_bits == 0:
                    secret_idx += 1
                    secret_bits = min(seed_rem_bits, 8)
                    secret_val = data.secret[secret_idx]
                    seed_rem_bits -= secret_bits
                chunk_bits = min(secret_bits, MoneroPolyseedMnemonicConst.SHARE_BITS - word_bits)
                secret_bits -= chunk_bits
                word_bits += chunk_bits
                word_val <<= chunk_bits
                word_val |= (secret_val >> secret_bits) & ((1 << chunk_bits) - 1)

            word_val <<= 1
            extra_bits -= 1
            word_val |= (extra_val >> extra_bits) & 1
            coeffs[MoneroPolyseedMnemonicConst.POLY_NUM_CHECK_DIGITS + i] = word_val
            word_val = 0
            word_bits = 0

        return coeffs

    @staticmethod
    def PolyToData(coeffs: List[int]) -> MoneroPolyseedDecodedData:
        """
        Convert 16 polynomial coefficients to decoded data.
        Faithful port of polyseed_poly_to_data from gf.c.

        Args:
            coeffs (list[int]): 16 polynomial coefficients

        Returns:
            MoneroPolyseedDecodedData: Decoded polyseed data
        """
        checksum = coeffs[0]

        extra_val = 0
        extra_bits = 0

        secret = bytearray(MoneroPolyseedMnemonicConst.SECRET_SIZE)
        secret_idx = 0
        secret_bits = 0

        for i in range(MoneroPolyseedMnemonicConst.POLY_NUM_CHECK_DIGITS,
                       MoneroPolyseedMnemonicConst.NUM_WORDS):
            word_val = coeffs[i]

            extra_val <<= 1
            extra_val |= word_val & 1
            word_val >>= 1
            word_bits = MoneroPolyseedMnemonicConst.GF_BITS - 1
            extra_bits += 1

            while word_bits > 0:
                if secret_bits == 8:
                    secret_idx += 1
                    secret_bits = 0
                chunk_bits = min(word_bits, 8 - secret_bits)
                word_bits -= chunk_bits
                chunk_mask = (1 << chunk_bits) - 1
                if chunk_bits < 8:
                    secret[secret_idx] <<= chunk_bits
                secret[secret_idx] |= (word_val >> word_bits) & chunk_mask
                secret_bits += chunk_bits

        birthday = extra_val & MoneroPolyseedMnemonicConst.DATE_MASK
        features = extra_val >> MoneroPolyseedMnemonicConst.DATE_BITS

        return MoneroPolyseedDecodedData(
            secret=bytes(secret),
            birthday=birthday,
            features=features,
            checksum=checksum,
        )


