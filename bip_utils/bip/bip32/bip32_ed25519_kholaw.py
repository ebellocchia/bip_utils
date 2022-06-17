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
from typing import Tuple
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_base import Bip32BaseUtils, Bip32Base
from bip_utils.bip.bip32.bip32_ed25519_slip_base import Bip32Ed25519SlipBaseConst
from bip_utils.bip.bip32.bip32_key_data import Bip32ChainCode, Bip32KeyIndex
from bip_utils.bip.bip32.bip32_key_net_ver import Bip32KeyNetVersions
from bip_utils.ecc import EllipticCurveGetter, EllipticCurveTypes, Ed25519KholawPrivateKey, Ed25519KholawPublicKey
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

        # Compute kL and kR
        kl_bytes, kr_bytes = cls._HashRepeatedly(seed_bytes)
        # Tweak kL bytes
        kl_bytes = cls._TweakMasterKeyBits(kl_bytes)

        # Compute chain code
        chain_code_bytes = CryptoUtils.HmacSha256(cls._MasterKeyHmacKey(), b"\x01" + seed_bytes)
        # Compute private key
        priv_key = Ed25519KholawPrivateKey.FromBytes(kl_bytes + kr_bytes)

        return cls(priv_key=priv_key,
                   pub_key=None,
                   chain_code=Bip32ChainCode(chain_code_bytes),
                   curve_type=cls.CurveType(),
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
        assert self.m_priv_key is not None

        # Get elliptic curve
        curve = EllipticCurveGetter.FromType(self.CurveType())

        # Get index bytes
        index_bytes = index.ToBytes(endianness="little")

        # Compute Z and chain code
        if index.IsHardened():
            z_bytes = CryptoUtils.HmacSha512(
                self.ChainCode().ToBytes(),
                b"\x00" + self.m_priv_key.Raw().ToBytes() + index_bytes
            )
            chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
                self.ChainCode().ToBytes(),
                b"\x01" + self.m_priv_key.Raw().ToBytes() + index_bytes
            )[1]
        else:
            z_bytes = CryptoUtils.HmacSha512(
                self.ChainCode().ToBytes(),
                b"\x02" + self.m_pub_key.RawCompressed().ToBytes()[1:] + index_bytes
            )
            chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
                self.ChainCode().ToBytes(),
                b"\x03" + self.m_pub_key.RawCompressed().ToBytes()[1:] + index_bytes
            )[1]

        # ZL is the left 28-byte part of Z
        zl_int = BytesUtils.ToInteger(z_bytes[:28], endianness="little")
        # ZR is the right 32-byte part of Z
        zr_int = BytesUtils.ToInteger(z_bytes[32:], endianness="little")

        # Compute kL
        kl_int = (zl_int * 8) + BytesUtils.ToInteger(self.m_priv_key.Raw().ToBytes()[:32], endianness="little")
        if kl_int % curve.Order() == 0:
            raise Bip32KeyError("Computed private child key is not valid, very unlucky index")
        # Compute kR
        kr_int = (zr_int + BytesUtils.ToInteger(self.m_priv_key.Raw().ToBytes()[32:], endianness="little")) % 2**256
        # Compute private key
        priv_key = Ed25519KholawPrivateKey.FromBytes(
            IntegerUtils.ToBytes(kl_int, Ed25519KholawPrivateKey.Length() // 2, endianness="little")
            + IntegerUtils.ToBytes(kr_int, Ed25519KholawPrivateKey.Length() // 2, endianness="little")
        )

        return Bip32Ed25519Kholaw(
            priv_key=priv_key,
            pub_key=None,
            chain_code=Bip32ChainCode(chain_code_bytes),
            curve_type=self.CurveType(),
            depth=self.Depth().Increase(),
            index=index,
            fprint=self.m_pub_key.FingerPrint(),
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

        # Get elliptic curve
        curve = EllipticCurveGetter.FromType(self.CurveType())

        # Get index bytes
        index_bytes = index.ToBytes(endianness="little")

        # Compute Z and chain code
        z_bytes = CryptoUtils.HmacSha512(
            self.ChainCode().ToBytes(),
            b"\x02" + self.m_pub_key.RawCompressed().ToBytes()[1:] + index_bytes
        )
        chain_code_bytes = Bip32BaseUtils.HmacSha512Halves(
            self.ChainCode().ToBytes(),
            b"\x03" + self.m_pub_key.RawCompressed().ToBytes()[1:] + index_bytes
        )[1]

        # ZL is the left 28-byte part of Z
        zl_int = BytesUtils.ToInteger(z_bytes[:28], endianness="little")

        # Compute the new public key point: PKEY + 8ZL * G
        pub_key_point = self.m_pub_key.Point() + ((zl_int * 8) * curve.Generator())
        # If the public key is the identity point (0, 1) discard the child
        if pub_key_point.X() == 0 and pub_key_point.Y() == 1:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index")

        return Bip32Ed25519Kholaw(
            priv_key=None,
            pub_key=Ed25519KholawPublicKey.FromPoint(pub_key_point),
            chain_code=Bip32ChainCode(chain_code_bytes),
            curve_type=self.CurveType(),
            depth=self.Depth().Increase(),
            index=index,
            fprint=self.m_pub_key.FingerPrint(),
            key_net_ver=self.KeyNetVersions()
        )

    @classmethod
    def _HashRepeatedly(cls,
                        data_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Continue to hash the data bytes until the third highest bit of the last byte is not zero.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            tuple[bytes, bytes]: Two halves of the computed hash
        """
        kl_bytes, kr_bytes = Bip32BaseUtils.HmacSha512Halves(cls._MasterKeyHmacKey(), data_bytes)
        if BitUtils.AreBitsSet(kl_bytes[31], 0x20):
            return cls._HashRepeatedly(kl_bytes + kr_bytes)
        return kl_bytes, kr_bytes

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
        # Set the second highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)
