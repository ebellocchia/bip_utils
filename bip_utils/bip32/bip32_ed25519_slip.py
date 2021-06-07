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
from bip_utils.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.bip32.bip32_base import Bip32Base
from bip_utils.conf import Bip32Conf, KeyNetVersions
from bip_utils.ecc import EllipticCurveTypes
from bip_utils.utils import ConvUtils


class Bip32Ed25519SlipConst:
    """ Class container for BIP32 ed25519 constants. """

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.ED25519
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY: bytes = b"ed25519 seed"


class Bip32Ed25519Slip(Bip32Base):
    """ BIP32 secp256k1 class. It allows master key generation and children keys derivation using ed25519 curve.
    The "Slip" in the class name is due to the fact that there are different derivation schemes using ed25519 curve and
    this one is based on SLIP-0010.
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
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeed(seed_bytes,
                             Bip32Ed25519SlipConst.MASTER_KEY_HMAC_KEY,
                             key_net_ver,
                             Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: str,
                        key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                           : Seed bytes
            path (str)                                   : Path
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeedAndPath(seed_bytes,
                                    Bip32Ed25519SlipConst.MASTER_KEY_HMAC_KEY,
                                    path,
                                    key_net_ver,
                                    Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                                : Extended key string
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls._FromExtendedKey(key_str,
                                    key_net_ver,
                                    Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromPrivateKey(cls,
                       key_bytes: bytes,
                       key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> Bip32Base:
        """ Create a Bip32 object from the specified private key.
        The key will be considered a master key with the chain code set to zero,
        since there is no way to recover the key derivation data.

        Args:
            key_bytes (bytes)                            : Key bytes
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls._FromPrivateKey(key_bytes,
                                   key_net_ver,
                                   Bip32Ed25519SlipConst.CURVE_TYPE)

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
    # Private methods
    #

    def _CkdPriv(self,
                 index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using private derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Index as bytes
        index_bytes = ConvUtils.IntegerToBytes(int(index), bytes_num=4)

        # Data for HMAC
        data = b"\x00" + self.m_priv_key.Raw().ToBytes() + index_bytes

        # Compute HMAC halves
        i_l, i_r = self._HmacHalves(data)

        # Construct and return a new Bip32 object
        return Bip32Ed25519Slip(secret=i_l,
                                chain_code=i_r,
                                curve_type=self.CurveType(),
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
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Not supported by Ed25519 SLIP-0010
        pass
