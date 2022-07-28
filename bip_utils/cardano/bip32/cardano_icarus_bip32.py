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
Module for Cardano Icarus BIP32 keys derivation.

References:
    https://github.com/satoshilabs/slips/blob/master/slip-0023.md
    https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
    https://cips.cardano.org/cips/cip3/icarus.md
"""

# Imports
from bip_utils.bip.bip32 import Bip32Base, Bip32Ed25519Kholaw, Bip32KeyData, Bip32KeyNetVersions
from bip_utils.ecc import Ed25519KholawPrivateKey
from bip_utils.utils.misc import BitUtils, CryptoUtils


class CardanoIcarusBip32Const:
    """Class container for Cardano Icarus BIP32 constants."""

    # PBKDF2 password
    PBKDF2_PASSWORD: str = ""
    # PBKDF2 rounds
    PBKDF2_ROUNDS: int = 4096
    # PBKDF2 output length in bytes
    PBKDF2_OUT_BYTE_LEN: int = 96


class CardanoIcarusBip32(Bip32Ed25519Kholaw):
    """
    Cardano Icarus BIP32 class.
    It allows master key generation and children keys derivation for Cardano Icarus.
    Derivation based on Khovratovich/Law paper with a different algorithm for master key generation.
    """

    @classmethod
    def _MasterKeyFromSeed(cls,
                           seed_bytes: bytes,
                           key_net_ver: Bip32KeyNetVersions) -> Bip32Base:
        """
        Generate a master key from the specified seed and return a Bip32 object (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                      : Seed bytes
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        key_bytes = CryptoUtils.Pbkdf2HmacSha512(CardanoIcarusBip32Const.PBKDF2_PASSWORD,
                                                 seed_bytes,
                                                 CardanoIcarusBip32Const.PBKDF2_ROUNDS,
                                                 CardanoIcarusBip32Const.PBKDF2_OUT_BYTE_LEN)
        key_bytes = cls._TweakMasterKeyBits(key_bytes)

        return cls(priv_key=Ed25519KholawPrivateKey.FromBytes(key_bytes[:Ed25519KholawPrivateKey.Length()]),
                   pub_key=None,
                   key_data=Bip32KeyData(chain_code=key_bytes[Ed25519KholawPrivateKey.Length():]),
                   curve_type=cls.CurveType(),
                   key_net_ver=key_net_ver)

    @staticmethod
    def _TweakMasterKeyBits(key_bytes: bytes) -> bytes:
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
        # Clear the highest 3 bits of the last byte of kL
        key_bytes[31] = BitUtils.ResetBits(key_bytes[31], 0xE0)
        # Set the second highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)
