# Copyright (c) 2022 Emanuele Bellocchia
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
Module for Cardano Icarus master key generation.

References:
    https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
    https://cips.cardano.org/cips/cip3/icarus.md
"""

# Imports
from typing import Tuple

from bip_utils.bip.bip32 import IBip32MstKeyGenerator
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from bip_utils.ecc import Ed25519KholawPrivateKey
from bip_utils.utils.crypto import Pbkdf2HmacSha512
from bip_utils.utils.misc import BitUtils


class CardanoIcarusMasterKeyGeneratorConst:
    """Class container for Cardano Icarus master key generator constants."""

    # PBKDF2 password
    PBKDF2_PASSWORD: str = ""
    # PBKDF2 rounds
    PBKDF2_ROUNDS: int = 4096
    # PBKDF2 output length in bytes
    PBKDF2_OUT_BYTE_LEN: int = 96


class CardanoIcarusMstKeyGenerator(IBip32MstKeyGenerator):
    """
    Cardano Icarus master key generator class.
    It allows master keys generation in according to Cardano Icarus.
    """

    @classmethod
    def GenerateFromSeed(cls,
                         seed_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Generate a master key from the specified seed.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)

        Raises:
            Bip32KeyError: If the seed is not suitable for master key generation
            ValueError: If seed length is not valid
        """
        if len(seed_bytes) < Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN:
            raise ValueError(f"Invalid seed length ({len(seed_bytes)})")

        key_bytes = Pbkdf2HmacSha512.DeriveKey(CardanoIcarusMasterKeyGeneratorConst.PBKDF2_PASSWORD,
                                               seed_bytes,
                                               CardanoIcarusMasterKeyGeneratorConst.PBKDF2_ROUNDS,
                                               CardanoIcarusMasterKeyGeneratorConst.PBKDF2_OUT_BYTE_LEN)
        key_bytes = cls.__TweakMasterKeyBits(key_bytes)

        return key_bytes[:Ed25519KholawPrivateKey.Length()], key_bytes[Ed25519KholawPrivateKey.Length():]

    @staticmethod
    def __TweakMasterKeyBits(key_bytes: bytes) -> bytes:
        """
        Tweak master key bits.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bytes: Tweaked key bytes
        """
        key_bytes = bytearray(key_bytes)
        # Clear the lowest 3 bits of the first byte of kL
        key_bytes[0] = BitUtils.ResetBits(key_bytes[0], 0x07)
        # Clear the highest 3 bits of the last byte of kL (standard kholaw only clears the highest one)
        key_bytes[31] = BitUtils.ResetBits(key_bytes[31], 0xE0)
        # Set the second-highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)
