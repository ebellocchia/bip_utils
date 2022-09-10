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
from bip_utils.bip.bip32 import Bip32KeyIndex, Bip32KholawEd25519KeyDerivatorBase, Bip32PublicKey
from bip_utils.ecc import EllipticCurve, IPoint
from bip_utils.utils.misc import BytesUtils, IntegerUtils


class CardanoByronLegacyKeyDerivator(Bip32KholawEd25519KeyDerivatorBase):
    """
    Cardano Byron legacy key derivator class.
    It allows keys derivation for Cardano-Byron (legacy, used by old versions of Daedalus).
    Derivation based on BIP32 ed25519 Khovratovich/Law with some differences on keys computation.
    """

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
                               kl_bytes: bytes,
                               curve: EllipticCurve) -> bytes:
        """
        Compute the new private key left part for private derivation.

        Args:
            zl_bytes (bytes)            : Leftmost Z 32-byte
            kl_bytes (bytes)            : Leftmost private key 32-byte
            curve (EllipticCurve object): EllipticCurve object

        Returns:
            bytes: Leftmost new private key 32-byte
        """
        zl8_bytes = BytesUtils.MultiplyScalarNoCarry(zl_bytes, 8)

        zl8_int = BytesUtils.ToInteger(zl8_bytes, endianness="little")
        kl_int = BytesUtils.ToInteger(kl_bytes, endianness="little")

        return IntegerUtils.ToBytes((zl8_int + kl_int) % curve.Order(), bytes_num=32, endianness="little")

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
        return BytesUtils.AddNoCarry(zr_bytes, kr_bytes)

    @staticmethod
    def _NewPublicKeyPoint(pub_key: Bip32PublicKey,
                           zl_bytes: bytes) -> IPoint:
        """
        Compute new public key point for public derivation.

        Args:
            pub_key (Bip32PublicKey object): Bip32PublicKey object
            zl_bytes (bytes)              : Leftmost Z 32-byte

        Returns:
            IPoint object: IPoint object
        """

        # Compute the new public key point: PKEY + 8ZL * G
        zl8_int = BytesUtils.ToInteger(BytesUtils.MultiplyScalarNoCarry(zl_bytes, 8),
                                       endianness="little")
        return pub_key.Point() + (zl8_int * pub_key.Curve().Generator())
