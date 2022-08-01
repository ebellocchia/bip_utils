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
Module for BIP32 keys derivation based on ed25519 curve (Khovratovich/Law version).
Reference: https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf
"""

# Imports
from typing import Tuple, Union
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_base import Bip32BaseUtils, Bip32Base
from bip_utils.bip.bip32.bip32_const import Bip32Const
from bip_utils.bip.bip32.bip32_ed25519_slip_base import Bip32Ed25519SlipBaseConst
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyIndex, Bip32KeyData
from bip_utils.bip.bip32.bip32_key_net_ver import Bip32KeyNetVersions
from bip_utils.bip.bip32.bip32_path import Bip32Path
from bip_utils.ecc import (
    EllipticCurveGetter, EllipticCurveTypes, Ed25519KholawPublicKey, Ed25519KholawPrivateKey,
    IPoint, IPublicKey, IPrivateKey
)
from bip_utils.utils.misc import BitUtils, BytesUtils, CryptoUtils, IntegerUtils


class Bip32Ed25519KholawConst:
    """Class container for BIP32 Khovratovich/Law ed25519 constants."""

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.ED25519_KHOLAW
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY: bytes = Bip32Ed25519SlipBaseConst.MASTER_KEY_HMAC_KEY


class Bip32Ed25519Kholaw(Bip32Base):
    """
    BIP32 ed25519 Khovratovich/Law class.
    It allows master key generation and children keys derivation using ed25519 curve.
    Derivation based on Khovratovich/Law paper.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: Bip32KeyNetVersions = Bip32Const.KHOLAW_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                      : Seed bytes
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: kholaw key net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return super().FromSeed(seed_bytes, key_net_ver)

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: Union[str, Bip32Path],
                        key_net_ver: Bip32KeyNetVersions = Bip32Const.KHOLAW_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                      : Seed bytes
            path (str or Bip32Path object)          : Path
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: kholaw key net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed length is too short
            Bip32PathError: If the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return super().FromSeedAndPath(seed_bytes, path, key_net_ver)

    @classmethod
    def FromExtendedKey(cls,
                        ex_key_str: str,
                        key_net_ver: Bip32KeyNetVersions = Bip32Const.KHOLAW_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified extended key.

        Args:
            ex_key_str (str)                        : Extended key string
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: kholaw key net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return super().FromExtendedKey(ex_key_str, key_net_ver)

    @classmethod
    def FromPrivateKey(cls,
                       priv_key: Union[bytes, IPrivateKey],
                       key_data: Bip32KeyData = Bip32KeyData(),
                       key_net_ver: Bip32KeyNetVersions = Bip32Const.KHOLAW_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified private key and derivation data.
        If only the private key bytes are specified, the key will be considered a master key with
        the chain code set to zero, since there is no way to recover the key derivation data.

        Args:
            priv_key (bytes or IPrivateKey)         : Private key
            key_data (Bip32KeyData object, optional): Key data (default: all zeros)
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: kholaw key net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return super().FromPrivateKey(priv_key, key_data, key_net_ver)

    @classmethod
    def FromPublicKey(cls,
                      pub_key: Union[bytes, IPublicKey],
                      key_data: Bip32KeyData = Bip32KeyData(),
                      key_net_ver: Bip32KeyNetVersions = Bip32Const.KHOLAW_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified public key and derivation data.
        If only the public key bytes are specified, the key will be considered a master key with
        the chain code set to zero, since there is no way to recover the key derivation data.

        Args:
            pub_key (bytes or IPublicKey)           : Public key
            key_data (Bip32KeyData object, optional): Key data (default: all zeros)
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: kholaw key net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return super().FromPublicKey(pub_key, key_data, key_net_ver)

    #
    # Public methods
    # Not-hardened private derivation and public derivation are always supported
    #

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Return the elliptic curve type.

        Returns:
            EllipticCurveTypes: Curve type
        """
        return Bip32Ed25519KholawConst.CURVE_TYPE

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

    @staticmethod
    def _MasterKeyHmacKey() -> bytes:
        """
        Return the HMAC key for generating the master key.

        Returns:
            bytes: HMAC key
        """
        return Bip32Ed25519KholawConst.MASTER_KEY_HMAC_KEY

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

        # Compute kL and kR
        kl_bytes, kr_bytes = cls.__HashRepeatedly(seed_bytes, 1)
        # Tweak kL bytes
        kl_bytes = cls._TweakMasterKeyBits(kl_bytes)

        # Compute chain code
        chain_code_bytes = CryptoUtils.HmacSha256(cls._MasterKeyHmacKey(),
                                                  b"\x01" + seed_bytes)
        # Compute private key
        priv_key = Ed25519KholawPrivateKey.FromBytes(kl_bytes + kr_bytes)

        return cls(priv_key=priv_key,
                   pub_key=None,
                   key_data=Bip32KeyData(chain_code=chain_code_bytes),
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
        # Clear the highest bit of the last byte of kL
        key_bytes[31] = BitUtils.ResetBits(key_bytes[31], 0x80)
        # Set the second-highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)

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
        assert self.m_priv_key is not None

        # Get index bytes
        index_bytes = self._SerializeIndex(index)
        # Get keys bytes
        priv_key_bytes = self.m_priv_key.Raw().ToBytes()
        pub_key_bytes = self.m_pub_key.RawCompressed().ToBytes()[1:]

        # Compute Z and chain code
        if index.IsHardened():
            z_bytes = CryptoUtils.HmacSha512(
                self.ChainCode().ToBytes(),
                b"\x00" + priv_key_bytes + index_bytes
            )
            chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
                self.ChainCode().ToBytes(),
                b"\x01" + priv_key_bytes + index_bytes
            )[1]
        else:
            z_bytes = CryptoUtils.HmacSha512(
                self.ChainCode().ToBytes(),
                b"\x02" + pub_key_bytes + index_bytes
            )
            chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
                self.ChainCode().ToBytes(),
                b"\x03" + pub_key_bytes + index_bytes
            )[1]

        # Compute the left and right part of the new private key
        kl_bytes = self._NewPrivateKeyLeftPart(z_bytes[:32], priv_key_bytes[:32])
        kr_bytes = self._NewPrivateKeyRightPart(z_bytes[32:], priv_key_bytes[32:])

        return self.__class__(
            priv_key=Ed25519KholawPrivateKey.FromBytes(kl_bytes + kr_bytes),
            pub_key=None,
            key_data=Bip32KeyData(
                chain_code=chain_code_bytes,
                depth=self.Depth().Increase(),
                index=index,
                parent_fprint=self.m_pub_key.FingerPrint()
            ),
            curve_type=self.CurveType(),
            key_net_ver=self.KeyNetVersions()
        )

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

        # Get index bytes
        index_bytes = self._SerializeIndex(index)
        # Get keys bytes
        pub_key_bytes = self.m_pub_key.RawCompressed().ToBytes()[1:]

        # Compute Z and chain code
        z_bytes = CryptoUtils.HmacSha512(
            self.ChainCode().ToBytes(),
            b"\x02" + pub_key_bytes + index_bytes
        )
        chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
            self.ChainCode().ToBytes(),
            b"\x03" + pub_key_bytes + index_bytes
        )[1]

        # Compute the new public key point
        pub_key_point = self._NewPublicKeyPoint(self.m_pub_key.KeyObject(), z_bytes[:32])
        # If the public key is the identity point (0, 1) discard the child
        if pub_key_point.X() == 0 and pub_key_point.Y() == 1:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index")

        return self.__class__(
            priv_key=None,
            pub_key=Ed25519KholawPublicKey.FromPoint(pub_key_point),
            key_data=Bip32KeyData(
                chain_code=chain_code_bytes,
                depth=self.Depth().Increase(),
                index=index,
                parent_fprint=self.m_pub_key.FingerPrint()
            ),
            curve_type=self.CurveType(),
            key_net_ver=self.KeyNetVersions()
        )

    #
    # Private methods
    #

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
            tuple[bytes, bytes]: Two halves of the computed hash
        """
        kl_bytes, kr_bytes = Bip32BaseUtils.HmacSha512Halves(cls._MasterKeyHmacKey(), data_bytes)
        if BitUtils.AreBitsSet(kl_bytes[31], 0x20):
            return cls.__HashRepeatedly(kl_bytes + kr_bytes, itr_num + 1)
        return kl_bytes, kr_bytes

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
        return index.ToBytes(endianness="little")

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
        curve = EllipticCurveGetter.FromType(Bip32Ed25519Kholaw.CurveType())

        zl_int = BytesUtils.ToInteger(zl_bytes[:28], endianness="little")
        kl_int = BytesUtils.ToInteger(kl_bytes, endianness="little")

        prvl_int = (zl_int * 8) + kl_int
        # Discard child if multiple of curve order
        if prvl_int % curve.Order() == 0:
            raise Bip32KeyError("Computed child key is not valid, very unlucky index")

        return IntegerUtils.ToBytes(prvl_int, bytes_num=32, endianness="little")

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
        zr_int = BytesUtils.ToInteger(zr_bytes, endianness="little")
        kpr_int = BytesUtils.ToInteger(kr_bytes, endianness="little")
        kr_int = (zr_int + kpr_int) % (2 ** 256)

        return IntegerUtils.ToBytes(kr_int, bytes_num=32, endianness="little")

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
        zl_int = BytesUtils.ToInteger(zl_bytes[:28], endianness="little")
        return pub_key.Point() + ((zl_int * 8) * curve.Generator())
