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

"""Module with BIP32 base class."""

# Imports
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Union, Tuple
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_const import Bip32Const
from bip_utils.bip.bip32.bip32_key_data import (
    Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyIndex, Bip32KeyData
)
from bip_utils.bip.bip32.bip32_key_net_ver import Bip32KeyNetVersions
from bip_utils.bip.bip32.bip32_key_ser import Bip32KeyDeserializer
from bip_utils.bip.bip32.bip32_keys import Bip32PrivateKey, Bip32PublicKey
from bip_utils.bip.bip32.bip32_path import Bip32Path, Bip32PathParser
from bip_utils.ecc import EllipticCurveGetter, EllipticCurveTypes, IPrivateKey, IPublicKey
from bip_utils.utils.crypto import HmacSha512


class Bip32BaseConst:
    """Class container for BIP32 base constants."""

    # Minimum length in bytes for seed
    SEED_MIN_BYTE_LEN: int = 16
    # HMAC half-length in bytes
    HMAC_HALF_BYTE_LEN: int = HmacSha512.DigestSize() // 2


class Bip32BaseUtils:
    """Class container for BIP32 base utility functions."""

    @staticmethod
    def HmacSha512Halves(key_bytes: bytes,
                         data_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Calculate the HMAC-SHA512 of input data using the chain code as key.
        Returns a tuple of the left and right halves of the HMAC.

        Args:
            key_bytes (bytes) : Key bytes
            data_bytes (bytes): Data bytes

        Returns:
            tuple[bytes, bytes]: Left and right halves of the HMAC
        """
        hmac = HmacSha512.QuickDigest(key_bytes, data_bytes)
        return hmac[:Bip32BaseConst.HMAC_HALF_BYTE_LEN], hmac[Bip32BaseConst.HMAC_HALF_BYTE_LEN:]


class Bip32Base(ABC):
    """
    BIP32 base class.
    It allows master key generation and children keys derivation in according to BIP-0032/SLIP-0010.
    It shall be derived to implement derivation for a specific elliptic curve.
    """

    m_priv_key: Optional[Bip32PrivateKey]
    m_pub_key: Bip32PublicKey

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                      : Seed bytes
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: BIP32 main net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        if not cls._IsSeedLengthValid(seed_bytes):
            raise ValueError(f"Invalid seed length ({len(seed_bytes)})")
        return cls._MasterKeyFromSeed(seed_bytes, key_net_ver)

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: Union[str, Bip32Path],
                        key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                      : Seed bytes
            path (str or Bip32Path object)          : Path
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: BIP32 main net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed length is too short
            Bip32PathError: If the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Create Bip32 object and derive path
        return cls.FromSeed(seed_bytes, key_net_ver).DerivePath(path)

    @classmethod
    def FromExtendedKey(cls,
                        ex_key_str: str,
                        key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified extended key.

        Args:
            ex_key_str (str)                        : Extended key string
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: BIP32 main net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """

        # De-serialize key
        deser_key = Bip32KeyDeserializer.DeserializeKey(ex_key_str, key_net_ver)
        # Get key parts
        key_bytes, key_data, is_public = deser_key.KeyBytes(), deser_key.KeyData(), deser_key.IsPublic()

        # If depth is zero, fingerprint shall be the master one and child index shall be zero
        if key_data.Depth() == 0:
            if not key_data.ParentFingerPrint().IsMasterKey():
                raise Bip32KeyError(
                    f"Invalid extended master key (wrong fingerprint: {key_data.ParentFingerPrint().ToHex()})"
                )
            if key_data.Index() != 0:
                raise Bip32KeyError(f"Invalid extended master key (wrong child index: {key_data.Index().ToInt()})")

        return cls(
            priv_key=key_bytes if not is_public else None,
            pub_key=key_bytes if is_public else None,
            key_data=key_data,
            curve_type=cls.CurveType(),
            key_net_ver=key_net_ver
        )

    @classmethod
    def FromPrivateKey(cls,
                       priv_key: Union[bytes, IPrivateKey],
                       key_data: Bip32KeyData = Bip32KeyData(),
                       key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified private key and derivation data.
        If only the private key bytes are specified, the key will be considered a master key with
        the chain code set to zero, since there is no way to recover the key derivation data.

        Args:
            priv_key (bytes or IPrivateKey)         : Private key
            key_data (Bip32KeyData object, optional): Key data (default: all zeros)
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: BIP32 main net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls(
            priv_key=priv_key,
            pub_key=None,
            key_data=key_data,
            curve_type=cls.CurveType(),
            key_net_ver=key_net_ver
        )

    @classmethod
    def FromPublicKey(cls,
                      pub_key: Union[bytes, IPublicKey],
                      key_data: Bip32KeyData = Bip32KeyData(),
                      key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> Bip32Base:
        """
        Create a Bip32 object from the specified public key and derivation data.
        If only the public key bytes are specified, the key will be considered a master key with
        the chain code set to zero, since there is no way to recover the key derivation data.

        Args:
            pub_key (bytes or IPublicKey)           : Public key
            key_data (Bip32KeyData object, optional): Key data (default: all zeros)
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object (default: BIP32 main net version)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls(
            priv_key=None,
            pub_key=pub_key,
            key_data=key_data,
            curve_type=cls.CurveType(),
            key_net_ver=key_net_ver
        )

    #
    # Public methods
    #

    def __init__(self,
                 priv_key: Optional[Union[bytes, IPrivateKey]],
                 pub_key: Optional[Union[bytes, IPublicKey]],
                 key_data: Bip32KeyData,
                 curve_type: EllipticCurveTypes,
                 key_net_ver: Bip32KeyNetVersions) -> None:
        """
        Construct class.

        Args:
            priv_key (bytes or IPrivateKey)         : Private key (None for a public-only object)
            pub_key (bytes or IPublicKey)           : Public key (only needed for a public-only object)
                                                      If priv_key is not None, it'll be discarded
            key_data (Bip32KeyData object)          : Key data
            curve_type (EllipticCurveTypes)         : Elliptic curve type
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object

        Raises:
            Bip32KeyError: If the constructed key is not valid
        """
        curve = EllipticCurveGetter.FromType(curve_type)

        # Private key object
        if priv_key is not None:
            # Check that key type matches the Bip curve
            if not isinstance(priv_key, bytes) and not isinstance(priv_key, curve.PrivateKeyClass()):
                raise Bip32KeyError(f"Invalid private key class, a {curve.Name()} key is required")

            self.m_priv_key = Bip32PrivateKey.FromBytesOrKeyObject(priv_key,
                                                                   key_data,
                                                                   key_net_ver,
                                                                   curve_type)
            self.m_pub_key = self.m_priv_key.PublicKey()
        # Public-only object
        else:
            # Check that key type matches the Bip curve
            if not isinstance(pub_key, bytes) and not isinstance(pub_key, curve.PublicKeyClass()):
                raise Bip32KeyError(f"Invalid public key class, a {curve.Name()} key is required")

            self.m_priv_key = None
            self.m_pub_key = Bip32PublicKey.FromBytesOrKeyObject(pub_key,
                                                                 key_data,
                                                                 key_net_ver,
                                                                 curve_type)

    def ChildKey(self,
                 index: Union[int, Bip32KeyIndex]) -> Bip32Base:
        """
        Create and return a child key of the current one with the specified index.
        The index shall be hardened using HardenIndex method to use the private derivation algorithm.

        Args:
            index (int or Bip32KeyIndex object): Index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        index = self.__GetIndex(index)
        return self._ValidateAndCkdPriv(index) if not self.IsPublicOnly() else self._ValidateAndCkdPub(index)

    def DerivePath(self,
                   path: Union[str, Bip32Path]) -> Bip32Base:
        """
        Derive children keys from the specified path.

        Args:
            path (str or Bip32Path object): Path

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
            Bip32PathError: If the path is not valid
            ValueError: If the path is a master path and the key is a child key
        """
        path = self.__GetPath(path)
        if self.Depth() > 0 and path.IsAbsolute():
            raise ValueError("Absolute paths can only be derived from a master key, not child ones")

        bip32_obj = self
        # Derive children keys
        for path_elem in path:
            bip32_obj = bip32_obj.ChildKey(path_elem)

        return bip32_obj

    def ConvertToPublic(self) -> None:
        """Convert the object into a public one."""
        self.m_priv_key = None

    def IsPublicOnly(self) -> bool:
        """
        Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_priv_key is None

    def PrivateKey(self) -> Bip32PrivateKey:
        """
        Return private key object.

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object

        Raises:
            Bip32KeyError: If internal key is public-only
        """
        if self.IsPublicOnly():
            raise Bip32KeyError("Public-only deterministic keys have no private half")

        assert isinstance(self.m_priv_key, Bip32PrivateKey)
        return self.m_priv_key

    def PublicKey(self) -> Bip32PublicKey:
        """
        Return public key object.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return self.m_pub_key

    def KeyNetVersions(self) -> Bip32KeyNetVersions:
        """
        Get key net versions.

        Returns:
            Bip32KeyNetVersions object: Bip32KeyNetVersions object
        """
        return self.m_pub_key.KeyNetVersions()

    def Depth(self) -> Bip32Depth:
        """
        Get current depth.

        Returns:
            Bip32Depth object: Current depth
        """
        return self.m_pub_key.Data().Depth()

    def Index(self) -> Bip32KeyIndex:
        """
        Get current index.

        Returns:
            Bip32KeyIndex object: Current index
        """
        return self.m_pub_key.Data().Index()

    def ChainCode(self) -> Bip32ChainCode:
        """
        Get chain code.

        Returns:
            Bip32ChainCode: Chain code
        """
        return self.m_pub_key.ChainCode()

    def FingerPrint(self) -> Bip32FingerPrint:
        """
        Get public key fingerprint.

        Returns:
            Bip32FingerPrint object: Public key fingerprint bytes
        """
        return self.m_pub_key.FingerPrint()

    def ParentFingerPrint(self) -> Bip32FingerPrint:
        """
        Get parent fingerprint.

        Returns:
            Bip32FingerPrint object: Parent fingerprint bytes
        """
        return self.m_pub_key.Data().ParentFingerPrint()

    #
    # Protected methods
    #

    @staticmethod
    def _IsSeedLengthValid(seed_bytes: bytes) -> bool:
        """
        Get if the seed length is valid.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return len(seed_bytes) >= Bip32BaseConst.SEED_MIN_BYTE_LEN

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
        curve_type = cls.CurveType()
        priv_key_cls = EllipticCurveGetter.FromType(curve_type).PrivateKeyClass()

        # Compute HMAC, retry if the resulting private key is not valid
        hmac = b""
        hmac_data = seed_bytes
        success = False

        while not success:
            hmac = HmacSha512.QuickDigest(cls._MasterKeyHmacKey(), hmac_data)
            # If private key is not valid, the new HMAC data is the current HMAC
            success = priv_key_cls.IsValidBytes(hmac[:Bip32BaseConst.HMAC_HALF_BYTE_LEN])
            if not success:
                hmac_data = hmac

        # Create BIP32 by splitting the HMAC into two 32-byte sequences
        return cls(priv_key=hmac[:Bip32BaseConst.HMAC_HALF_BYTE_LEN],
                   pub_key=None,
                   key_data=Bip32KeyData(chain_code=hmac[Bip32BaseConst.HMAC_HALF_BYTE_LEN:]),
                   curve_type=curve_type,
                   key_net_ver=key_net_ver)

    def _ValidateAndCkdPriv(self,
                            index: Bip32KeyIndex) -> Bip32Base:
        """
        Check the key index validity and create a child key of the specified index using private derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Check if supported
        if not index.IsHardened() and not self.IsPrivateUnhardenedDerivationSupported():
            raise Bip32KeyError("Private child derivation with not-hardened index is not supported")

        return self._CkdPriv(index)

    def _ValidateAndCkdPub(self,
                           index: Bip32KeyIndex) -> Bip32Base:
        """
        Check the key index validity and create a child key of the specified index using public derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Check if supported
        if not self.IsPublicDerivationSupported():
            raise Bip32KeyError("Public child derivation is not supported")

        # Hardened index is not supported for public derivation
        if index.IsHardened():
            raise Bip32KeyError("Public child derivation cannot be used to create a hardened child key")

        return self._CkdPub(index)

    #
    # Private methods
    #

    @staticmethod
    def __GetIndex(index: Union[int, Bip32KeyIndex]) -> Bip32KeyIndex:
        """
        Get index object.

        Args:
            index (int or Bip32KeyIndex): Index

        Returns:
            Bip32KeyIndex object: Bip32KeyIndex object
        """
        return Bip32KeyIndex(index) if isinstance(index, int) else index

    @staticmethod
    def __GetPath(path: Union[str, Bip32Path]) -> Bip32Path:
        """
        Get path object.

        Args:
            path (str or Bip32Path): Path

        Returns:
            Bip32Path object: Bip32Path object
        """
        return Bip32PathParser.Parse(path) if isinstance(path, str) else path

    #
    # Abstract methods
    #

    @staticmethod
    @abstractmethod
    def IsPublicDerivationSupported() -> bool:
        """
        Get if public derivation is supported.

        Returns:
            bool: True if supported, false otherwise.
        """

    @staticmethod
    @abstractmethod
    def IsPrivateUnhardenedDerivationSupported() -> bool:
        """
        Get if private derivation with not-hardened indexes is supported.

        Returns:
            bool: True if supported, false otherwise.
        """

    @staticmethod
    @abstractmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Return the elliptic curve type.

        Returns:
            EllipticCurveTypes: Curve type
        """

    @staticmethod
    @abstractmethod
    def _MasterKeyHmacKey() -> bytes:
        """
        Return the HMAC key for generating the master key.

        Returns:
            bytes: HMAC key
        """

    @abstractmethod
    def _CkdPriv(self,
                 index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using private derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

    @abstractmethod
    def _CkdPub(self,
                index: Bip32KeyIndex) -> Bip32Base:
        """
        Create a child key of the specified index using public derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
