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

"""Module for BIP32 extended key serialization/deserialization."""

# Imports
from typing import Optional, Tuple
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_key_data import (
    Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyIndex, Bip32KeyNetVersions, Bip32KeyData
)
from bip_utils.ecc import IPublicKey, IPrivateKey
from bip_utils.utils.misc import BytesUtils


class Bip32KeyDeserConst:
    """Class container for BIP32 key serialize constants."""

    # Extended public key length in bytes
    EXTENDED_PUB_KEY_BYTE_LEN: int = 78
    # Extended private key length in bytes
    EXTENDED_PRIV_KEY_BYTE_LEN: Tuple[int, int] = (78, 110)


class Bip32KeyDeserializer:
    """
    BIP32key deserializer class.
    It deserializes a key.
    """

    m_key_str: str
    m_key_bytes: bytes
    m_is_public: bool
    m_key_data: Optional[Bip32KeyData]

    def __init__(self,
                 key_str: str) -> None:
        """
        Construct class.

        Args:
            key_str (str): Serialized key string
        """

        self.m_key_str = key_str
        self.m_key_bytes = b""
        self.m_is_public = False
        self.m_key_data = None

    def DeserializeKey(self,
                       key_net_ver: Bip32KeyNetVersions) -> None:
        """
        Deserialize a key.

        Args:
            key_net_ver (Bip32KeyNetVersions object): Key net versions object
        """

        # Decode key
        ex_key_bytes = Base58Decoder.CheckDecode(self.m_key_str)

        # Get if key is public/private depending on net version
        key_net_ver_got = ex_key_bytes[:Bip32KeyNetVersions.Length()]
        if key_net_ver_got == key_net_ver.Public():
            self.m_is_public = True
        elif key_net_ver_got == key_net_ver.Private():
            self.m_is_public = False
        else:
            raise Bip32KeyError(
                f"Invalid extended key (wrong net version: {BytesUtils.ToHexString(key_net_ver_got)})"
            )

        # Check length
        if self.m_is_public and len(ex_key_bytes) != Bip32KeyDeserConst.EXTENDED_PUB_KEY_BYTE_LEN:
            raise Bip32KeyError(f"Invalid extended public key (wrong length: {len(ex_key_bytes)})")
        elif not self.m_is_public and len(ex_key_bytes) not in Bip32KeyDeserConst.EXTENDED_PRIV_KEY_BYTE_LEN:
            raise Bip32KeyError(f"Invalid extended private key (wrong length: {len(ex_key_bytes)})")

        # De-serialize key
        depth = ex_key_bytes[4]
        fprint = ex_key_bytes[5:9]
        index = BytesUtils.ToInteger(ex_key_bytes[9:13])
        chain_code = ex_key_bytes[13:45]
        self.m_key_bytes = ex_key_bytes[45:]
        self.m_key_data = Bip32KeyData(key_net_ver,
                                       Bip32Depth(depth),
                                       Bip32KeyIndex(index),
                                       Bip32ChainCode(chain_code),
                                       Bip32FingerPrint(fprint))

    def GetKeyParts(self) -> Tuple[bytes, Bip32KeyData]:
        """
        Get deserialized key parts.

        Returns:
            tuple[bytes, Bip32KeyData]: Deserialized key parts
        """
        assert self.m_key_data is not None, "Deserialize key before getting key parts"
        return self.m_key_bytes, self.m_key_data

    def IsPublic(self) -> bool:
        """
        Get if deserialized key is public.

        Returns:
            bool: True if public, false otherwise
        """
        return self.m_is_public


class Bip32PrivateKeySerializer:
    """
    BIP32 private key serializer class.
    It serializes private keys.
    """

    @staticmethod
    def Serialize(priv_key: IPrivateKey,
                  key_data: Bip32KeyData) -> str:
        """
        Serialize a private key.

        Args:
            priv_key (IPrivateKey object): IPrivateKey object
            key_data (BipKeyData object) : Key data

        Returns:
            str: Serialized private key
        """
        return Bip32KeySerializer.Serialize(b"\x00" + priv_key.Raw().ToBytes(),
                                            key_data.KeyNetVersions().Private(),
                                            key_data.Depth(),
                                            key_data.Index(),
                                            key_data.ChainCode(),
                                            key_data.ParentFingerPrint())


class Bip32PublicKeySerializer:
    """
    BIP32 public key serializer class.
    It serializes public keys.
    """

    @staticmethod
    def Serialize(pub_key: IPublicKey,
                  key_data: Bip32KeyData) -> str:
        """
        Serialize the a public key.

        Args:
            pub_key (IPublicKey object) : IPublicKey object
            key_data (BipKeyData object): Key data

        Returns:
            str: Serialized public key
        """
        return Bip32KeySerializer.Serialize(pub_key.RawCompressed().ToBytes(),
                                            key_data.KeyNetVersions().Public(),
                                            key_data.Depth(),
                                            key_data.Index(),
                                            key_data.ChainCode(),
                                            key_data.ParentFingerPrint())


class Bip32KeySerializer:
    """
    BIP32 key serializer class.
    It serializes private/public keys.
    """

    @staticmethod
    def Serialize(key_bytes: bytes,
                  key_net_ver: bytes,
                  depth: Bip32Depth,
                  index: Bip32KeyIndex,
                  chain_code: Bip32ChainCode,
                  fprint: Bip32FingerPrint) -> str:
        """
        Serialize the specified key bytes.

        Args:
            key_bytes (bytes)                 : Key bytes
            key_net_ver (bytes)               : Key net version
            depth (Bip32Depth object)         : Key depth
            index (Bip32KeyIndex object)      : Key index
            chain_code (Bip32ChainCode object): Key chain code
            fprint (Bip32FingerPrint object)  : Key fingerprint

        Returns:
            str: Serialized key
        """

        # Serialize key
        ser_key = key_net_ver + bytes(depth) + bytes(fprint) + bytes(index) + bytes(chain_code) + key_bytes
        # Encode it
        return Base58Encoder.CheckEncode(ser_key)
