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
from abc import ABC, abstractmethod
from typing import Union, Tuple
from bip_utils.bip32.bip32_ex import Bip32KeyError, Bip32PathError
from bip_utils.bip32.bip32_key_data import Bip32FingerPrint, Bip32KeyIndex, Bip32KeyData
from bip_utils.bip32.bip32_keys import Bip32PrivateKey, Bip32PublicKey
from bip_utils.bip32.bip32_key_ser import Bip32KeyDeserializer
from bip_utils.bip32.bip32_path import Bip32Path, Bip32PathParser
from bip_utils.conf import Bip32Conf, KeyNetVersions
from bip_utils.ecc import EllipticCurveTypes
from bip_utils.utils import CryptoUtils


class Bip32BaseConst:
    """ Class container for BIP32 base constants. """

    # Minimum length in bits for seed
    SEED_MIN_BIT_LEN: int = 128
    # HMAC half length
    HMAC_HALF_LEN: int = 32


class Bip32Base(ABC):
    """ BIP32 base class. It allows master key generation and children keys derivation in according to BIP-0032/SLIP-0010.
    It shall be derived to implement derivation for a specific elliptic curve.
    BIP-0032 specifications: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    SLIP-0010 specifications: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    """

    #
    # Class methods for construction
    # They are meant to be called by children classes, that's why they are protected
    #

    @classmethod
    def _FromSeed(cls,
                  seed_bytes: bytes,
                  hmac_key_bytes: bytes,
                  key_net_ver: KeyNetVersions,
                  curve_type: EllipticCurveTypes) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                 : Seed bytes
            hmac_key_bytes (bytes)             : Key for HMAC computation
            curve_type (EllipticCurveTypes)    : Elliptic curve type
            key_net_ver (KeyNetVersions object): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Check seed length
        if len(seed_bytes) * 8 < Bip32BaseConst.SEED_MIN_BIT_LEN:
            raise ValueError("Seed length is too small, it shall be at least %d bit" % Bip32BaseConst.SEED_MIN_BIT_LEN)

        # Compute HMAC
        hmac = CryptoUtils.HmacSha512(hmac_key_bytes, seed_bytes)
        # Create BIP32 by splitting the HMAC into two 32-byte sequences
        return cls(secret=hmac[:Bip32BaseConst.HMAC_HALF_LEN],
                   chain_code=hmac[Bip32BaseConst.HMAC_HALF_LEN:],
                   curve_type=curve_type,
                   key_net_ver=key_net_ver)

    @classmethod
    def _FromSeedAndPath(cls,
                         seed_bytes: bytes,
                         hmac_key_bytes: bytes,
                         path: str,
                         key_net_ver: KeyNetVersions,
                         curve_type: EllipticCurveTypes) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                 : Seed bytes
            hmac_key_bytes (bytes)             : Key for HMAC computation
            path (str)                         : Path
            curve_type (EllipticCurveTypes)    : Elliptic curve type
            key_net_ver (KeyNetVersions object): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Create Bip32 object and derive path
        bip32_ctx = cls._FromSeed(seed_bytes, hmac_key_bytes, key_net_ver, curve_type)
        return bip32_ctx.DerivePath(path)

    @classmethod
    def _FromExtendedKey(cls,
                         key_str: str,
                         key_net_ver: KeyNetVersions,
                         curve_type: EllipticCurveTypes) -> Bip32Base:
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                      : Extended key string
            key_net_ver (KeyNetVersions object): KeyNetVersions object
            curve_type (EllipticCurveTypes)    : Elliptic curve type

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """

        # De-serialize key
        key_deser = Bip32KeyDeserializer(key_str)
        key_deser.DeserializeKey(key_net_ver)
        # Get key parts
        secret, key_data = key_deser.GetKeyParts()
        is_public = key_deser.IsPublic()

        # If depth is zero, fingerprint shall be the master one and child index shall be zero
        if key_data.Depth() == 0:
            if not key_data.ParentFingerPrint().IsMasterKey():
                raise Bip32KeyError("Invalid extended master key (wrong fingerprint)")
            if key_data.Index().ToInt() != 0:
                raise Bip32KeyError("Invalid extended master key (wrong child index)")

        # If private key, the first byte shall be zero and shall be removed
        if not is_public:
            if secret[0] != 0:
                raise Bip32KeyError("Invalid extended key (wrong secret)")
            secret = secret[1:]

        return cls(secret=secret,
                   chain_code=key_data.ChainCode(),
                   curve_type=curve_type,
                   depth=key_data.Depth(),
                   index=key_data.Index(),
                   fprint=key_data.ParentFingerPrint(),
                   is_public=is_public,
                   key_net_ver=key_data.KeyNetVersions())

    @classmethod
    def _FromPrivateKey(cls,
                        key_bytes: bytes,
                        key_net_ver: KeyNetVersions,
                        curve_type: EllipticCurveTypes) -> Bip32Base:
        """ Create a Bip32 object from the specified private key.
        The key will be considered a master key with the chain code set to zero,
        since there is no way to recover the key derivation data.

        Args:
            key_bytes (bytes)                  : Key bytes
            key_net_ver (KeyNetVersions object): KeyNetVersions object
            curve_type (EllipticCurveTypes)    : Elliptic curve type

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls(secret=key_bytes,
                   chain_code=b"\x00" * Bip32BaseConst.HMAC_HALF_LEN,
                   curve_type=curve_type,
                   is_public=False,
                   key_net_ver=key_net_ver)

    #
    # Public methods
    #

    def __init__(self,
                 secret: bytes,
                 chain_code: bytes,
                 curve_type: EllipticCurveTypes,
                 depth: int = 0,
                 index: Bip32KeyIndex = Bip32KeyIndex(0),
                 fprint: Bip32FingerPrint = Bip32FingerPrint(),
                 is_public: bool = False,
                 key_net_ver: KeyNetVersions = Bip32Conf.KEY_NET_VER.Main()) -> None:
        """ Construct class from secret and chain code.

        Args:
            secret (bytes)                               : Source bytes to generate the keypair
            chain_code (bytes)                           : 32-byte representation of the chain code
            curve_type (EllipticCurveTypes)              : Elliptic curve type
            depth (int, optional)                        : Child depth, parent increments its own by one when
                                                           assigning this (default: 0)
            index (Bip32KeyIndex object, optional)       : Child index (default: 0)
            fprint (Bip32FingerPrint, optional)          : Parent fingerprint (default: master key)
            is_public (bool, optional)                   : If true, this keypair will only contain a public key and can
                                                           only create a public key chain  (default: false)
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net by default)

        Raises:
            Bip32KeyError: If the key constructed from the secret is not valid
        """
        if not is_public:
            self.m_priv_key = Bip32PrivateKey(secret,
                                              Bip32KeyData(key_net_ver, depth, index, chain_code, fprint),
                                              curve_type)
            self.m_pub_key = self.m_priv_key.PublicKey()
        else:
            self.m_priv_key = None
            self.m_pub_key = Bip32PublicKey(secret,
                                            Bip32KeyData(key_net_ver, depth, index, chain_code, fprint),
                                            curve_type)

    def ChildKey(self,
                 index: Union[int, Bip32KeyIndex]) -> Bip32Base:
        """ Create and return a child key of the current one at the specified index.
        The index shall be hardened using HardenIndex method to use the private derivation algorithm.

        Args:
            index (int, Bip32KeyIndex object): Index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        if isinstance(index, int):
            index = Bip32KeyIndex(index)

        return self._ValidateAndCkdPriv(index) if not self.IsPublicOnly() else self._ValidateAndCkdPub(index)

    def DerivePath(self,
                   path: Union[str, Bip32Path]) -> Bip32Base:
        """ Derive children keys from the specified path.

        Args:
            path (str): Path

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
        """

        # Parse path
        if isinstance(path, str):
            path = Bip32PathParser.Parse(path)

        # Check result
        if not path.IsValid():
            raise Bip32PathError("The specified path is not valid")

        bip32_obj = self
        # Derive children keys
        for path_elem in path:
            bip32_obj = bip32_obj.ChildKey(int(path_elem))

        return bip32_obj

    def ConvertToPublic(self) -> None:
        """ Convert a private Bip32 object into a public one. """
        self.m_priv_key = None

    def IsPublicOnly(self) -> bool:
        """ Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_priv_key is None

    def CurveType(self) -> EllipticCurveTypes:
        """ Return the elliptic curve type.

        Returns:
            EllipticCurveTypes: Curve type
        """
        return self.m_pub_key.CurveType()

    def PrivateKey(self) -> Bip32PrivateKey:
        """ Return private key object.

        Returns:
            BipPrivateKey object: BipPrivateKey object

        Raises:
            Bip32KeyError: If internal key is public-only
        """
        if self.IsPublicOnly():
            raise Bip32KeyError("Public-only deterministic keys have no private half")
        return self.m_priv_key

    def PublicKey(self) -> Bip32PublicKey:
        """ Return public key object.

        Returns:
            BipPublicKey object: BipPublicKey object
        """
        return self.m_pub_key

    def KeyNetVersions(self) -> KeyNetVersions:
        """ Get key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """
        return self.m_pub_key.Data().KeyNetVersions()

    def Depth(self) -> int:
        """ Get current depth.

        Returns:
            int: Current depth
        """
        return self.m_pub_key.Data().Depth()

    def Index(self) -> Bip32KeyIndex:
        """ Get current index.

        Returns:
            Bip32KeyIndex: Current index
        """
        return self.m_pub_key.Data().Index()

    def ChainCode(self) -> bytes:
        """ Get current chain code.

        Returns:
            bytes: Current chain code
        """
        return self.m_pub_key.Data().ChainCode()

    def FingerPrint(self) -> Bip32FingerPrint:
        """ Get public key fingerprint.

        Returns:
            Bip32FingerPrint object: Public key fingerprint bytes
        """
        return self.m_pub_key.FingerPrint()

    def ParentFingerPrint(self) -> Bip32FingerPrint:
        """ Get parent fingerprint.

        Returns:
            bytes: Parent fingerprint bytes
        """
        return self.m_pub_key.Data().ParentFingerPrint()

    #
    # Protected methods
    #

    def _ValidateAndCkdPriv(self,
                            index: Bip32KeyIndex) -> Bip32Base:
        """ Check the key index and create a child key of the specified index
        using private derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Check if supported
        if not index.IsHardened() and not self.IsPrivateUnhardenedDerivationSupported():
            raise Bip32KeyError("Private child derivation with not-hardened index is not supported")

        return self._CkdPriv(index)

    def _ValidateAndCkdPub(self,
                           index: Bip32KeyIndex) -> Bip32Base:
        """ Check the key index validaity and create a child key of the specified index
        using public derivation.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

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

    def _HmacHalves(self,
                    data_bytes: bytes) -> Tuple[bytes, bytes]:
        """ Calculate the HMAC-SHA512 of input data using the chain code as key and returns a tuple
        of the left and right halves of the HMAC.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            tuple: Left and right halves of the HMAC
        """

        # Use chain as HMAC key
        hmac = CryptoUtils.HmacSha512(self.ChainCode(), data_bytes)
        return hmac[:Bip32BaseConst.HMAC_HALF_LEN], hmac[Bip32BaseConst.HMAC_HALF_LEN:]

    #
    # Abstract methods
    #

    @classmethod
    @abstractmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: KeyNetVersions) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                           : Seed bytes
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        pass

    @classmethod
    @abstractmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: str,
                        key_net_ver: KeyNetVersions) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                           : Seed bytes
            path (str)                                   : Path
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        pass

    @classmethod
    @abstractmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        key_net_ver: KeyNetVersions) -> Bip32Base:
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                                : Extended key string
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        pass

    @classmethod
    @abstractmethod
    def FromPrivateKey(cls,
                       key_bytes: bytes,
                       key_net_ver: KeyNetVersions) -> Bip32Base:
        """ Create a Bip32 object from the specified private key.
        The key will be considered a master key with the chain code set to zero,
        since there is no way to recover the key derivation data.

        Args:
            key_bytes (bytes)                  : Key bytes
            key_net_ver (KeyNetVersions object): KeyNetVersions object

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        pass

    @staticmethod
    @abstractmethod
    def IsPublicDerivationSupported() -> bool:
        """ Get if public derivation is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        pass

    @staticmethod
    @abstractmethod
    def IsPrivateUnhardenedDerivationSupported() -> bool:
        """ Get if private derivation with not-hardened indexes is supported.

        Returns:
            bool: True if supported, false otherwise.
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
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
        pass
