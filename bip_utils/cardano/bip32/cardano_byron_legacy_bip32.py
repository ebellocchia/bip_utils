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
Module for Cardano Byron legacy BIP32 keys derivation.

References:
    https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
    https://cips.cardano.org/cips/cip3/byron.md
"""

# Imports
from typing import Tuple
from bip_utils.bip.bip32 import Bip32Base, Bip32Ed25519Kholaw, Bip32KeyIndex, Bip32KeyData, Bip32KeyNetVersions
from bip_utils.bip.bip32.bip32_base import Bip32BaseUtils
from bip_utils.ecc import Ed25519KholawPrivateKey, EllipticCurveGetter, IPublicKey, IPoint
from bip_utils.ecc.ed25519.lib import ed25519_nacl_wrapper
from bip_utils.utils.misc import BitUtils, BytesUtils, CryptoUtils


class CardanoByronLegacyBip32Const:
    """Class container for Cardano Byron legacy BIP32 constants."""

    # HMAC message format
    HMAC_MESSAGE_FORMAT: bytes = b"Root Seed Chain %d"


class CardanoByronLegacyBip32(Bip32Ed25519Kholaw):
    """
    Cardano Byron legacy BIP32 class, used by old versions of Daedalus.
    It allows master key generation and children keys derivation for Cardano-Byron (legacy).
    Derivation based on Khovratovich/Law paper with a different algorithm for master key generation and keys derivation.
    """

    @classmethod
    def _MasterKeyFromSeed(cls,
                           seed_bytes: bytes,
                           key_net_ver: Bip32KeyNetVersions) -> Bip32Base:
        """
        Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                      : Seed bytes
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        key_bytes, chain_code_bytes = cls.__HashRepeatedly(seed_bytes, 1)
        return cls(priv_key=Ed25519KholawPrivateKey.FromBytes(key_bytes),
                   pub_key=None,
                   key_data=Bip32KeyData(chain_code=chain_code_bytes),
                   curve_type=cls.CurveType(),
                   key_net_ver=key_net_ver)

    #
    # Private methods
    #

    @classmethod
    def __HashRepeatedly(cls,
                         data_bytes: bytes,
                         itr_num: int) -> Tuple[bytes, bytes]:
        """
        Continue to hash the data bytes until the third highest bit of the last byte is not zero.

        Args:
            data_bytes (bytes): Data bytes
            itr_num (int)     : Iteration number

        Returns:
            tuple[bytes, bytes]: Key bytes (index 0) and chain code bytes (index 1)
        """
        il_bytes, ir_bytes = Bip32BaseUtils.HmacSha512Halves(
            data_bytes,
            CardanoByronLegacyBip32Const.HMAC_MESSAGE_FORMAT % itr_num
        )
        key_bytes = cls._TweakMasterKeyBits(CryptoUtils.Sha512(il_bytes))
        if BitUtils.AreBitsSet(key_bytes[31], 0x20):
            return cls.__HashRepeatedly(data_bytes, itr_num + 1)
        return key_bytes, ir_bytes

    #
    # Overridden methods
    #

    @staticmethod
    def _SerializeIndex(index: Bip32KeyIndex) -> bytes:
        """
        Serialize key index.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            bytes: Serialized index
        """
        return index.ToBytes(endianness="big")

    @staticmethod
    def _NewPrivateKeyLeftPart(zl_bytes: bytes,
                               kl_bytes: bytes) -> bytes:
        """
        Compute the new private key left part for private derivation.

        Args:
            zl_bytes (bytes): Leftmost Z 32-byte
            kl_bytes (bytes): Leftmost private key 32-byte

        Returns:
            bytes: Leftmost new private key 32-byte
        """
        zl8_bytes = BytesUtils.MultiplyScalar(zl_bytes, 8)
        return ed25519_nacl_wrapper.scalar_add(zl8_bytes, kl_bytes)

    @staticmethod
    def _NewPrivateKeyRightPart(zr_bytes: bytes,
                                kr_bytes: bytes) -> bytes:
        """
        Compute the new private key right part for private derivation.

        Args:
            zr_bytes (bytes): Rightmost Z 32-byte
            kr_bytes (bytes): Rightmost private key 32-byte

        Returns:
            bytes: Rightmost new private key 32-byte
        """
        return BytesUtils.Add(zr_bytes, kr_bytes)

    @staticmethod
    def _NewPublicKeyPoint(pub_key: IPublicKey,
                           zl_bytes: bytes) -> IPoint:
        """
        Compute new public key point for public derivation.

        Args:
            pub_key (IPublicKey object): Public key object
            zl_bytes (bytes)           : Leftmost Z 32-byte

        Returns:
            IPoint object: IPoint object
        """
        curve = EllipticCurveGetter.FromType(pub_key.CurveType())

        # Compute the new public key point: PKEY + 8ZL * G
        zl8_int = BytesUtils.ToInteger(BytesUtils.MultiplyScalar(zl_bytes, 8),
                                       endianness="little")
        return pub_key.Point() + (zl8_int * curve.Generator())
