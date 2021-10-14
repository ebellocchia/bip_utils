# Copyright (c) 2021 Emanuele Bellocchia
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

"""Module for BIP32 keys derivation based on nist256p1 curve."""

# Imports
from bip_utils.bip.bip32.bip32_base import Bip32Base
from bip_utils.bip.bip32.bip32_ecdsa_base import Bip32EcdsaBase
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.ecc import EllipticCurveTypes


class Bip32Nist256p1Const:
    """Class container for BIP32 nist256p1 constants."""

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.NIST256P1
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY: bytes = b"Nist256p1 seed"


class Bip32Nist256p1(Bip32EcdsaBase):
    """
    BIP32 nist256p1 class.
    It allows master key generation and children keys derivation using nist256p1 curve.
    """

    #
    # Public methods
    #

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Return the elliptic curve type.

        Returns:
            EllipticCurveTypes: Curve type
        """
        return Bip32Nist256p1Const.CURVE_TYPE

    #
    # Protected methods
    #

    @staticmethod
    def _MasterKeyHmacKey() -> bytes:
        """
        Return the HMAC key for generating the master key.

        Returns:
            bytes: HMAC key
        """
        return Bip32Nist256p1Const.MASTER_KEY_HMAC_KEY

    def _CkdPriv(self,
                 index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using private derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        return self._CkdPrivEcdsa(self, index)

    def _CkdPub(self,
                index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using public derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        return self._CkdPubEcdsa(self, index)
