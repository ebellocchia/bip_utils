# Copyright (c) 2020 Emanuele Bellocchia
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
from typing import Tuple
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip32_ex import Bip32KeyError
from bip_utils.conf import KeyNetVersions
from bip_utils.ecc import EcdsaPublicKey, EcdsaPrivateKey
from bip_utils.utils import ConvUtils


class Bip32KeyDeserConst:
    """ Class container for BIP32 key serialize constants. """

    # Extended key length
    EXTENDED_KEY_LEN: int = 78


class Bip32KeyDeserializer:
    """ BIP32key deserializer class. It deserializes a key. """

    def __init__(self,
                 key_str: str) -> None:
        """ Construct class.

        Args:
            key_str (str): Serialized key string
        """

        self.m_key_str = key_str
        self.m_depth = 0
        self.m_fprint = b""
        self.m_index = 0
        self.m_chain = b""
        self.m_secret = b""
        self.m_is_public = False

    def DeserializeKey(self,
                       key_net_ver: KeyNetVersions) -> None:
        """ Deserialize a key.

        Args:
            key_net_ver (KeyNetVersions object): Key net versions object
        """

        # Decode key
        key_bytes = Base58Decoder.CheckDecode(self.m_key_str)

        # Check length
        if len(key_bytes) != Bip32KeyDeserConst.EXTENDED_KEY_LEN:
            raise Bip32KeyError("Invalid extended key (wrong length)")

        # Get if key is public/private depending on net version
        if key_bytes[:4] == key_net_ver.Public():
            self.m_is_public = True
        elif key_bytes[:4] == key_net_ver.Private():
            self.m_is_public = False
        else:
            raise Bip32KeyError("Invalid extended key (wrong net version)")

        # De-serialize key
        self.m_depth = key_bytes[4]
        self.m_fprint = key_bytes[5:9]
        self.m_index = ConvUtils.BytesToInteger(key_bytes[9:13])
        self.m_chain = key_bytes[13:45]
        self.m_secret = key_bytes[45:78]

    def GetKeyParts(self) -> Tuple[int, bytes, int, bytes, bytes]:
        """ Get deserialized key parts.

        Returns:
            tuple: Deserialized key parts
        """
        return self.m_depth, self.m_fprint, self.m_index, self.m_chain, self.m_secret

    def IsPublic(self) -> bool:
        """ Get if deserialized key is public.

        Returns:
            bool: True if public, false otherwise
        """
        return self.m_is_public


class Bip32PrivateKeySerializer:
    """ BIP32 private key serializer class. It serializes private keys. """

    @staticmethod
    def Serialize(priv_key: EcdsaPrivateKey,
                  key_net_ver: KeyNetVersions,
                  depth: int,
                  fprint: bytes,
                  index: int,
                  chain: bytes) -> str:
        """ Serialize a private key.

        Args:
            priv_key (EcdsaPrivateKey object): EcdsaPrivateKey object
            key_net_ver (KeyNetVersions)     : KeyNetVersions object
            depth (int)                      : Key depth
            fprint (bytes)                   : Key fingerprint
            index (int)                      : Key index
            chain (bytes)                    : Key chain code

        Returns:
            str: Serialized private key
        """
        return Bip32KeySerializer.Serialize(b"\x00" + priv_key.Raw().ToBytes(),
                                            key_net_ver.Private(),
                                            depth,
                                            fprint,
                                            index,
                                            chain)


class Bip32PublicKeySerializer:
    """ BIP32 public key serializer class. It serializes public keys. """

    @staticmethod
    def Serialize(pub_key: EcdsaPublicKey,
                  key_net_ver: KeyNetVersions,
                  depth: int,
                  fprint: bytes,
                  index: int,
                  chain: bytes) -> str:
        """ Serialize the a public key.

        Args:
            pub_key (EcdsaPublicKey object): EcdsaPublicKey object
            key_net_ver (KeyNetVersions)   : KeyNetVersions object
            depth (int)                    : Key depth
            fprint (bytes)                 : Key fingerprint
            index (int)                    : Key index
            chain (bytes)                  : Key chain code

        Returns:
            str: Serialized public key
        """
        return Bip32KeySerializer.Serialize(pub_key.RawCompressed().ToBytes(),
                                            key_net_ver.Public(),
                                            depth,
                                            fprint,
                                            index,
                                            chain)


class Bip32KeySerializer:
    """ BIP32 key serializer class. It serializes private/public keys. """

    @staticmethod
    def Serialize(key_bytes: bytes,
                  key_net_ver: bytes,
                  depth: int,
                  fprint: bytes,
                  index: int,
                  chain: bytes) -> str:
        """ Serialize the specified key bytes.

        Args:
            key_bytes (bytes)  : Key bytes
            key_net_ver (bytes): Key net version
            depth (int): Key depth
            fprint (bytes): Key fingerprint
            index (int): Key index
            chain (bytes): Key chain code

        Returns:
            str: Serialized key
        """

        # Get bytes for serializing
        depth = depth.to_bytes(1, "big")
        index = index.to_bytes(4, "big")
        # Serialize key
        ser_key = key_net_ver + depth + fprint + index + chain + key_bytes
        # Encode it
        return Base58Encoder.CheckEncode(ser_key)
