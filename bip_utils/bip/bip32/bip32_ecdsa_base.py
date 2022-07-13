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

"""
Module with BIP32 base class for ECDSA curves.

References:
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    https://github.com/satoshilabs/slips/blob/master/slip-0010.md
"""

# Imports
from abc import ABC
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyIndex, Bip32KeyData
from bip_utils.bip.bip32.bip32_base import Bip32BaseUtils, Bip32Base
from bip_utils.ecc import EllipticCurveGetter
from bip_utils.utils.misc import BytesUtils, IntegerUtils


class Bip32EcdsaBase(Bip32Base, ABC):
    """
    BIP32 ECDSA base class.
    It implements the generic key derivation for ECDSA curves, since they share the same derivation scheme.
    It shall be derived by the specific ECDSA curve.
    """

    #
    # Public methods
    # Not-hardened private derivation and public derivation are always supported
    #

    @staticmethod
    def IsPublicDerivationSupported() -> bool:
        """
        Get if public derivation is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return True

    @staticmethod
    def IsPrivateUnhardenedDerivationSupported() -> bool:
        """
        Get if private derivation with not-hardened indexes is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return True

    #
    # Protected methods
    #

    @classmethod
    def _CkdPrivEcdsa(cls,
                      bip32_obj: Bip32Base,
                      index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using private derivation.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        assert bip32_obj.m_priv_key is not None

        # Get elliptic curve
        curve = EllipticCurveGetter.FromType(bip32_obj.CurveType())

        # Data for HMAC
        if index.IsHardened():
            data_bytes = b"\x00" + bip32_obj.m_priv_key.Raw().ToBytes() + bytes(index)
        else:
            data_bytes = bip32_obj.m_pub_key.RawCompressed().ToBytes() + bytes(index)

        # Compute HMAC halves
        i_l, i_r = Bip32BaseUtils.HmacSha512Halves(bip32_obj.ChainCode().ToBytes(), data_bytes)

        # Construct new key secret from i_l and current private key
        i_l_int = BytesUtils.ToInteger(i_l)
        key_int = BytesUtils.ToInteger(bip32_obj.m_priv_key.Raw().ToBytes())
        new_key_int = (i_l_int + key_int) % curve.Order()

        # Convert to string and pad with zeros
        new_priv_key_bytes = IntegerUtils.ToBytes(new_key_int).rjust(curve.PrivateKeyClass().Length(), b"\x00")

        # Construct and return a new Bip32 object
        return cls(priv_key=new_priv_key_bytes,
                   pub_key=None,
                   key_data=Bip32KeyData(
                       chain_code=i_r,
                       depth=bip32_obj.Depth().Increase(),
                       index=index,
                       parent_fprint=bip32_obj.m_pub_key.FingerPrint()
                   ),
                   curve_type=bip32_obj.CurveType(),
                   key_net_ver=bip32_obj.KeyNetVersions())

    @classmethod
    def _CkdPubEcdsa(cls,
                     bip32_obj: Bip32Base,
                     index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using public derivation.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        curve = EllipticCurveGetter.FromType(bip32_obj.CurveType())

        # Data for HMAC, same of __CkdPriv() for public child key
        data_bytes = bip32_obj.m_pub_key.RawCompressed().ToBytes() + bytes(index)

        # Get HMAC of data
        i_l, i_r = Bip32BaseUtils.HmacSha512Halves(bip32_obj.ChainCode().ToBytes(), data_bytes)

        # Try to construct a new public key from the curve point: pub_key_point + G*i_l
        try:
            new_point = bip32_obj.m_pub_key.Point() + (curve.Generator() * BytesUtils.ToInteger(i_l))
            pub_key = curve.PublicKeyClass().FromPoint(new_point)
        except ValueError as ex:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index") from ex
        # Construct and return a new Bip32 object
        return cls(priv_key=None,
                   pub_key=pub_key,
                   key_data=Bip32KeyData(
                       chain_code=i_r,
                       depth=bip32_obj.Depth().Increase(),
                       index=index,
                       parent_fprint=bip32_obj.m_pub_key.FingerPrint()
                   ),
                   curve_type=bip32_obj.CurveType(),
                   key_net_ver=bip32_obj.KeyNetVersions())
