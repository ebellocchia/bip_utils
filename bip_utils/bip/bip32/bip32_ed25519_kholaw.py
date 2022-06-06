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

"""Module for BIP32 keys derivation based on ed25519 curve (Khovratovich/Law version)."""

# Imports
from typing import Optional, Union
from bip_utils.bip.bip32.bip32_base import Bip32BaseUtils, Bip32Base
from bip_utils.bip.bip32.bip32_const import Bip32Const
from bip_utils.bip.bip32.bip32_ed25519_slip_base import Bip32Ed25519SlipBaseConst
from bip_utils.bip.bip32.bip32_key_data import (
    Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyIndex, Bip32KeyNetVersions
)
from bip_utils.ecc import EllipticCurveTypes, IPrivateKey, IPublicKey
from bip_utils.utils.misc import BitUtils, CryptoUtils


class Bip32Ed25519KholawConst:
    """Class container for BIP32 ed25519 constants."""

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.ED25519


class Bip32Ed25519Kholaw(Bip32Base):
    """
    BIP32 ed25519 class.
    It allows master key generation and children keys derivation using ed25519 curve.
    Derivation based on SLIP-0010.
    """

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

    def __init__(self,
                 priv_key: Optional[Union[bytes, IPrivateKey]],
                 priv_key_ext_bytes: bytes,
                 pub_key: Optional[Union[bytes, IPublicKey]],
                 chain_code: Bip32ChainCode,
                 curve_type: EllipticCurveTypes,
                 depth: Bip32Depth = Bip32Depth(0),
                 index: Bip32KeyIndex = Bip32KeyIndex(0),
                 fprint: Bip32FingerPrint = Bip32FingerPrint(),
                 key_net_ver: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS) -> None:
        """
        Construct class.

        Args:
            priv_key (bytes or IPrivateKey)                   : Private key (None for a public-only object)
            pub_key (bytes or IPublicKey)                     : Public key (only needed for a public-only object)
                                                                If priv_key is not None, it'll be discarded
            chain_code (Bip32ChainCode object)                : Chain code
            curve_type (EllipticCurveTypes)                   : Elliptic curve type
            depth (Bip32Depth object, optional)               : Child depth, parent increments its own by one when
                                                                assigning this (default: 0)
            index (Bip32KeyIndex object, optional)            : Child index (default: 0)
            fprint (Bip32FingerPrint object, optional)        : Parent fingerprint (default: master key)
            key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object (Bip32 main net by default)

        Raises:
            Bip32KeyError: If the constructed key is not valid
        """
        super().__init__(priv_key, pub_key, chain_code, curve_type, depth, index, fprint, key_net_ver)
        # This version uses an extended private key with doubled size (64-byte)
        # This is the 32-byte extended part of the private key
        self.m_priv_key_ext_bytes = priv_key_ext_bytes if priv_key is not None else None

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
        return Bip32Ed25519SlipBaseConst.MASTER_KEY_HMAC_KEY

    @classmethod
    def _FromSeed(cls,
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
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        curve_type = cls.CurveType()
        hmac_key = cls._MasterKeyHmacKey()

        # Continue until the third highest bit of the last byte ok kL is not zero
        kl, kr = Bip32BaseUtils.HmacSha512Halves(hmac_key, seed_bytes)
        while BitUtils.AreBitsSet(kl[31], 0x20):
            kl, kr = Bip32BaseUtils.HmacSha512Halves(hmac_key, kl + kr)

        kl = bytearray(kl)
        # Clear the lowest 3 bits of the first byte of kL
        kl[0] = BitUtils.ResetBits(kl[0], 0x03)
        # Clear the highest bit of the last byte of kL
        kl[31] = BitUtils.ResetBits(kl[31], 0x80)
        # Set the second highest bit of the last byte of kL
        kl[31] = BitUtils.SetBits(kl[31], 0x40)

        # Compute chain code
        chain_code_bytes = CryptoUtils.HmacSha256(hmac_key, b"\x01" + seed_bytes)

        return cls(priv_key=bytes(kl),
                   priv_key_ext_bytes=kr,
                   pub_key=None,
                   chain_code=Bip32ChainCode(chain_code_bytes),
                   curve_type=curve_type,
                   key_net_ver=key_net_ver)

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
