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


# Imports
from bip_utils.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.bip32.bip32_base import Bip32Base


class Bip32Ed25519SlipBaseConst:
    """ Class container for BIP32 ed25519 constants. """

    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY: bytes = b"ed25519 seed"


class Bip32Ed25519SlipBase(Bip32Base):
    """ BIP32 ed25519 base class. It allows master key generation and children keys derivation using ed25519 curve.
    The "Slip" in the class name is due to the fact that there are different derivation schemes using ed25519 curve and
    this one is based on SLIP-0010.
    It shall be derived by the specific ed25519 curve.
    """

    #
    # Public methods
    #

    @staticmethod
    def IsPublicDerivationSupported() -> bool:
        """ Get if public derivation is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return False

    @staticmethod
    def IsPrivateUnhardenedDerivationSupported() -> bool:
        """ Get if private derivation with not-hardened indexes is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return False

    #
    # Protected methods
    #

    @classmethod
    def _CkdPrivEd25519Slip(cls,
                            bip32_obj: Bip32Base,
                            index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using private derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Data for HMAC
        data = b"\x00" + bip32_obj.m_priv_key.Raw().ToBytes() + bytes(index)

        # Compute HMAC halves
        i_l, i_r = bip32_obj._HmacHalves(data)

        # Construct and return a new Bip32 object
        return cls(priv_key=i_l,
                   pub_key=None,
                   chain_code=i_r,
                   curve_type=bip32_obj.CurveType(),
                   depth=bip32_obj.Depth().Increase(),
                   index=index,
                   fprint=bip32_obj.m_pub_key.FingerPrint(),
                   key_net_ver=bip32_obj.KeyNetVersions())

    def _CkdPub(self,
                index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using public derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Not supported by Ed25519 SLIP-0010
        pass
