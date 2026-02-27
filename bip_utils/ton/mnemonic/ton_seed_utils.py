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
Module for TON seed utilities.
Reference: https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts
"""

# Imports
from bip_utils.utils.crypto.hmac import HmacSha512
from bip_utils.utils.crypto.pbkdf2 import Pbkdf2HmacSha512


class TonSeedUtilsConst:
    """Class container for TON seed utilities constants."""

    # Password seed
    PASSWORD_SEED_SALT_MOD: str = "TON fast seed version"
    PASSWORD_SEED_PBKDF2_ROUNDS: int = 1
    # Basic seed
    BASIC_SEED_SALT_MOD: str = "TON seed version"
    BASIC_SEED_PBKDF2_ROUNDS: int = 100000 // 256
    # Private key seed
    PRIV_KEY_SEED_SALT_MOD: str = "TON default seed"
    PRIV_KEY_SEED_PBKDF2_ROUNDS: int = 100000
    # HD key seed
    HD_KEY_SEED_SALT_MOD: str = "TON HD Keys seed"
    HD_KEY_SEED_PBKDF2_ROUNDS: int = 100000
    # Seed length in bytes
    SEED_LEN_BYTES: int = 64


class TonSeedUtils:
    """
    TON seed utilities class.
    It provides some utility functions for the seed generation and validation.
    """

    @staticmethod
    def GetEntropyBytes(mnemonic: str,
                        passphrase: str = "") -> bytes:
        """
        Get entropy bytes from mnemonic and passphrase.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic
            passphrase (str, optional)       : Passphrase (empty by default)

        Returns:
            bytes: Entropy bytes
        """
        return HmacSha512().QuickDigest(mnemonic, passphrase)

    @staticmethod
    def IsBasicSeed(entropy_bytes: bytes) -> bool:
        """
        Get if the entropy bytes are for a basic seed.

        Args:
            entropy_bytes (bytes): Entropy bytes to validate

        Returns:
            bool: True if the entropy bytes are for a basic seed, False otherwise
        """
        seed_bytes = Pbkdf2HmacSha512().DeriveKey(entropy_bytes,
                                                  TonSeedUtilsConst.BASIC_SEED_SALT_MOD,
                                                  TonSeedUtilsConst.BASIC_SEED_PBKDF2_ROUNDS,
                                                  TonSeedUtilsConst.SEED_LEN_BYTES)
        return seed_bytes[0] == 0

    @staticmethod
    def IsPasswordSeed(entropy_bytes: bytes) -> bool:
        """
        Get if the entropy bytes are for a password seed.

        Args:
            entropy_bytes (bytes): Entropy bytes to validate

        Returns:
            bool: True if the entropy bytes are for a password seed, False otherwise
        """
        seed_bytes = Pbkdf2HmacSha512().DeriveKey(entropy_bytes,
                                                  TonSeedUtilsConst.PASSWORD_SEED_SALT_MOD,
                                                  TonSeedUtilsConst.PASSWORD_SEED_PBKDF2_ROUNDS,
                                                  TonSeedUtilsConst.SEED_LEN_BYTES)
        return seed_bytes[0] == 1

    @classmethod
    def IsPasswordNeeded(cls,
                         mnemonic: str) -> bool:
        """
        Get if the mnemonic needs a password.

        Args:
            mnemonic (str): Mnemonic to check

        Returns:
            bool: True if the mnemonic needs a password, False otherwise
        """
        # Use entropy bytes without passphrase in according to Ton source code
        entropy_bytes = cls.GetEntropyBytes(mnemonic)
        return cls.IsPasswordSeed(entropy_bytes) and not cls.IsBasicSeed(entropy_bytes)

    @staticmethod
    def GetPrivateKeySeed(entropy_bytes: bytes) -> bytes:
        """
        Get the private key seed from entropy bytes.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            bytes: Private key seed bytes
        """
        return Pbkdf2HmacSha512().DeriveKey(entropy_bytes,
                                            TonSeedUtilsConst.PRIV_KEY_SEED_SALT_MOD,
                                            TonSeedUtilsConst.PRIV_KEY_SEED_PBKDF2_ROUNDS,
                                            TonSeedUtilsConst.SEED_LEN_BYTES)

    @staticmethod
    def GetHdKeySeed(entropy_bytes: bytes) -> bytes:
        """
        Get the HD key seed from entropy bytes.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            bytes: HD key seed bytes
        """
        return Pbkdf2HmacSha512().DeriveKey(entropy_bytes,
                                            TonSeedUtilsConst.HD_KEY_SEED_SALT_MOD,
                                            TonSeedUtilsConst.HD_KEY_SEED_PBKDF2_ROUNDS,
                                            TonSeedUtilsConst.SEED_LEN_BYTES)
