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
from __future__ import annotations
from bip_utils.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.bip32.bip32_base import Bip32BaseConst, Bip32Base
from bip_utils.conf import Bip32Conf, KeyNetVersions
from bip_utils.ecc import EllipticCurve, Secp256k1PublicKey, Secp256k1
from bip_utils.utils import ConvUtils


class Bip32Secp256k1Const:
    """ Class container for BIP32 secp256k1 constants. """

    # Elliptic curve
    CURVE: EllipticCurve = Secp256k1
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY: bytes = b"Bitcoin seed"


class Bip32Secp256k1(Bip32Base):
    """ BIP32 secp256k1 class. It allows master key generation and children keys derivation using secp256k1 curve.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                           : Seed bytes
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeed(seed_bytes,
                             Bip32Secp256k1Const.MASTER_KEY_HMAC_KEY,
                             key_net_ver,
                             Bip32Secp256k1Const.CURVE)

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: str,
                        key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                           : Seed bytes
            path (str)                                   : Path
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeedAndPath(seed_bytes,
                                    Bip32Secp256k1Const.MASTER_KEY_HMAC_KEY,
                                    path,
                                    key_net_ver,
                                    Bip32Secp256k1Const.CURVE)

    @classmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                                : Extended key string
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls._FromExtendedKey(key_str,
                                    key_net_ver,
                                    Bip32Secp256k1Const.CURVE)

    #
    # Public methods
    #

    def IsPublicDerivationSupported(self) -> bool:
        """ Get if public derivation is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return True

    def IsPrivateUnhardenedDerivationSupported(self) -> bool:
        """ Get if private derivation with not-hardened indexes is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        return True

    #
    # Private methods
    #

    def _CkdPriv(self,
                 index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using private derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Index as bytes
        index_bytes = ConvUtils.IntegerToBytes(int(index), bytes_num=4)

        # Data for HMAC
        if index.IsHardened():
            data = b"\x00" + self.m_priv_key.Raw().ToBytes() + index_bytes
        else:
            data = self.m_pub_key.RawCompressed().ToBytes() + index_bytes

        # Compute HMAC halves
        i_l, i_r = self._HmacHalves(data)

        # Construct new key secret from i_l and current private key
        i_l_int = ConvUtils.BytesToInteger(i_l)
        key_int = ConvUtils.BytesToInteger(self.m_priv_key.Raw().ToBytes())
        new_key_int = (i_l_int + key_int) % Secp256k1.Order()

        # Convert to string and left pad with zeros
        secret = ConvUtils.IntegerToBytes(new_key_int)
        secret = b"\x00" * (Bip32BaseConst.HMAC_HALF_LEN - len(secret)) + secret

        # Construct and return a new Bip32 object
        return Bip32Secp256k1(secret=secret,
                              chain_code=i_r,
                              curve=self.Curve(),
                              depth=self.Depth() + 1,
                              index=index,
                              fprint=self.m_pub_key.FingerPrint(),
                              is_public=False,
                              key_net_ver=self.KeyNetVersions())

    def _CkdPub(self,
                index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using public derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Data for HMAC, same of __CkdPriv() for public child key
        data = self.m_pub_key.RawCompressed().ToBytes() + ConvUtils.IntegerToBytes(int(index), bytes_num=4)

        # Get HMAC of data
        i_l, i_r = self._HmacHalves(data)

        # Try to construct a new public key from the curve point: pub_key_point + G*i_l
        try:
            new_point = self.m_pub_key.Point() + (Secp256k1.Generator() * ConvUtils.BytesToInteger(i_l))
            pub_key = Secp256k1PublicKey(new_point)
        except ValueError as ex:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index") from ex

        # Construct and return a new Bip32 object
        return Bip32Secp256k1(secret=pub_key.RawCompressed().ToBytes(),
                              chain_code=i_r,
                              curve=self.Curve(),
                              depth=self.Depth() + 1,
                              index=index,
                              fprint=self.m_pub_key.FingerPrint(),
                              is_public=True,
                              key_net_ver=self.KeyNetVersions())
