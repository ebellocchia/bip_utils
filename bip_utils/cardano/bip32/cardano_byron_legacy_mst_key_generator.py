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
Module for Cardano Byron legacy master key generation.

References:
    https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
    https://cips.cardano.org/cips/cip3/byron.md
"""

# Imports
from typing import Tuple

import cbor2

from bip_utils.bip.bip32 import IBip32MstKeyGenerator
from bip_utils.utils.crypto import HmacSha512, Sha512
from bip_utils.utils.misc import BitUtils


class CardanoByronLegacyMstKeyGeneratorConst:
    """Class container for Cardano Byron legacy BIP32 constants."""

    # HMAC message format
    HMAC_MESSAGE_FORMAT: bytes = b"Root Seed Chain %d"
    # Length in bytes for seed
    SEED_BYTE_LEN: int = 32


class CardanoByronLegacyMstKeyGenerator(IBip32MstKeyGenerator):
    """
    Cardano Byron legacy master key generator class.
    It allows master keys generation in according to Cardano Byron (legacy, used by old versions of Daedalus).
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
        if len(seed_bytes) != CardanoByronLegacyMstKeyGeneratorConst.SEED_BYTE_LEN:
            raise ValueError(f"Invalid seed length ({len(seed_bytes)})")
        return cls.__HashRepeatedly(cbor2.dumps(seed_bytes), 1)

    @classmethod
    def __HashRepeatedly(cls,
                         data_bytes: bytes,
                         itr_num: int) -> Tuple[bytes, bytes]:
        """
        Continue to hash the data bytes until the third-highest bit of the last byte is not zero.

        Args:
            data_bytes (bytes): Data bytes
            itr_num (int)     : Iteration number

        Returns:
            tuple[bytes, bytes]: Key bytes (index 0) and chain code bytes (index 1)
        """
        il_bytes, ir_bytes = HmacSha512.QuickDigestHalves(
            data_bytes,
            CardanoByronLegacyMstKeyGeneratorConst.HMAC_MESSAGE_FORMAT % itr_num
        )
        key_bytes = cls.__TweakMasterKeyBits(Sha512.QuickDigest(il_bytes))
        if BitUtils.AreBitsSet(key_bytes[31], 0x20):
            return cls.__HashRepeatedly(data_bytes, itr_num + 1)
        return key_bytes, ir_bytes

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
        # Clear the highest bit of the last byte of kL
        key_bytes[31] = BitUtils.ResetBits(key_bytes[31], 0x80)
        # Set the second-highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)
