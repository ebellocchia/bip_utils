# Copyright (c) 2014 Corgan Labs, 2020 Emanuele Bellocchia
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
from .base58   import Base58Decoder, Base58Encoder
from .bip32_ex import Bip32KeyError


class Bip32KeySerConst:
    """ Class container for BIP32 key serialize constants. """

    # Extended key length
    EXTENDED_KEY_LEN = 78


class Bip32KeyDeserializer:
    """ BIP32key deserializer class. It deserializes a key. """

    def __init__(self, key_str):
        """ Construct class.

        Args:
            key_str (str) : serialized key string
        """
        self.m_key_str   = key_str
        self.m_depth     = 0
        self.m_fprint    = b""
        self.m_child     = 0
        self.m_chain     = b""
        self.m_secret    = b""
        self.m_is_public = False

    def DeserializeKey(self, is_testnet, main_net_ver, test_net_ver):
        """ Deserialize a key.

        Args:
            is_testnet (bytes)   : true if test net, false if main net
            main_net_ver (bytes) : main net version bytes
            test_net_ver (bytes) : test net version bytes
        """

        # Decode key
        key_bytes = Base58Decoder.CheckDecode(self.m_key_str)

        # Check length
        if len(key_bytes) != Bip32KeySerConst.EXTENDED_KEY_LEN:
            raise Bip32KeyError("Invalid extended key (wrong length)")

        # Get net version
        net_ver = key_bytes[:4]

        # Get if key is public/private depending on main/test net
        if not is_testnet:
            if net_ver in main_net_ver.values():
                self.m_is_public = net_ver == main_net_ver["pub"]
            else:
                raise Bip32KeyError("Invalid extended key (wrong net version)")
        else:
            if net_ver in test_net_ver.values():
                self.m_is_public = net_ver == test_net_ver["pub"]
            else:
                raise Bip32KeyError("Invalid extended key (wrong net version)")

        # De-serialize key
        self.m_depth  = key_bytes[4]
        self.m_fprint = key_bytes[5:9]
        self.m_child  = int.from_bytes(key_bytes[9:13], "big")
        self.m_chain  = key_bytes[13:45]
        self.m_secret = key_bytes[45:78]

    def GetKeyParts(self):
        """ Get deserialized key parts.

        Returns (tuple):
            Deserialized key parts
        """
        return self.m_depth, self.m_fprint, self.m_child, self.m_chain, self.m_secret

    def IsPublic(self):
        """ Get if deserialized key is public.

        Returns (bool):
            True if public, false otherwise
        """
        return self.m_is_public


class Bip32KeySerializer:
    """ BIP32key serializer class. It serializes private/public keys. """

    def __init__(self, bip32_obj):
        """ Construct class.

        Args:
            bip32_obj (Bip32 object) : Bip32 object
        """
        self.m_bip32_obj = bip32_obj

    def SerializePublicKey(self, main_net_ver, test_net_ver):
        """ Serialize the Bip32 object public key.

        Args:
            main_net_ver (bytes) : main net version bytes
            test_net_ver (bytes) : test net version bytes

        Returns (bytes):
            Serialized public key
        """
        return self.__SerializeKey(self.m_bip32_obj.PublicKeyBytes(), main_net_ver, test_net_ver)

    def SerializePrivateKey(self, main_net_ver, test_net_ver):
        """ Serialize the Bip32 object private key.

        Args:
            main_net_ver (bytes) : main net version bytes
            test_net_ver (bytes) : test net version bytes

        Returns (str):
            Serialized private key
        """
        return self.__SerializeKey(b"\x00" + self.m_bip32_obj.PrivateKeyBytes(), main_net_ver, test_net_ver)

    def __SerializeKey(self, key_bytes, main_net_ver, test_net_ver):
        """ Serialize the specified key bytes.

        Args:
            key_bytes (bytes)    : key bytes
            main_net_ver (bytes) : main net version bytes
            test_net_ver (bytes) : test net version bytes

        Returns (str):
            Serialized key
        """

        # Get net version
        net_ver = main_net_ver if not self.m_bip32_obj.IsTestNet() else test_net_ver
        # Get Bip32 data for serializing
        depth  = self.m_bip32_obj.Depth().to_bytes(1, "big")
        fprint = self.m_bip32_obj.ParentFingerPrint()
        child  = self.m_bip32_obj.Index().to_bytes(4, "big")
        chain  = self.m_bip32_obj.Chain()
        # Serialize key
        ser_key = net_ver + depth + fprint + child + chain + key_bytes
        # Encode it
        return Base58Encoder.CheckEncode(ser_key)
