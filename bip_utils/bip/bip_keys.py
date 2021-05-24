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
from typing import Type
from bip_utils.bip.bip32_key_ser import Bip32PrivateKeySerializer, Bip32PublicKeySerializer
from bip_utils.conf import BipCoinBase, Bip44BitcoinMainNet, KeyNetVersions
from bip_utils.ecc import KeyBytes, EcdsaPrivateKey, EcdsaPublicKey
from bip_utils.wif import WifEncoder


class BipPublicKey:
    """ BIP public key class. It allows to get a public key in different formats. """

    def __init__(self,
                 pub_key: EcdsaPublicKey,
                 key_net_ver: KeyNetVersions,
                 depth: int,
                 fprint: bytes,
                 index: int,
                 chain: bytes,
                 coin_class: Type[BipCoinBase] = Bip44BitcoinMainNet) -> None:
        """ Construct class.

        Args:
            pub_key (EcdsaPublicKey object)                : EcdsaPublicKey object
            key_net_ver (KeyNetVersions)                   : KeyNetVersions object
            depth (int)                                    : Key depth
            fprint (bytes)                                 : Key fingerprint
            index (int)                                    : Key index
            chain (bytes)                                  : Key chain code
            coin_class (BipCoinBase child object, optional): BipCoinBase child object, Bip44BitcoinMainNet by default
        """
        self.m_pub_key = pub_key
        # Pre-compute serialized key and address
        self.m_ser_key = Bip32PublicKeySerializer.Serialize(pub_key,
                                                            key_net_ver,
                                                            depth,
                                                            fprint,
                                                            index,
                                                            chain)
        self.m_addr = coin_class.ComputeAddress(pub_key)

    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_pub_key.RawCompressed()

    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_pub_key.RawUncompressed()

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_ser_key

    def ToAddress(self) -> str:
        """ Return address correspondent tot he public key.

        Returns:
            str: Address
        """
        return self.m_addr


class BipPrivateKey:
    """ BIP private key class. It allows to get a private key in different formats. """

    def __init__(self,
                 priv_key: EcdsaPrivateKey,
                 key_net_ver: KeyNetVersions,
                 depth: int,
                 fprint: bytes,
                 index: int,
                 chain: bytes,
                 coin_class: Type[BipCoinBase] = Bip44BitcoinMainNet) -> None:
        """ Construct class.

        Args:
            priv_key (EcdsaPrivateKey object)              : EcdsaPrivateKey object
            key_net_ver (KeyNetVersions)                   : KeyNetVersions object
            depth (int)                                    : Key depth
            fprint (bytes)                                 : Key fingerprint
            index (int)                                    : Key index
            chain (bytes)                                  : Key chain code
            coin_class (BipCoinBase child object, optional): BipCoinBase child object, Bip44BitcoinMainNet by default

        Raises:
            Bip32KeyError: If the Bip32 object is public-only
        """
        self.m_priv_key = priv_key
        # Pre-compute serialized key
        self.m_ser_key = Bip32PrivateKeySerializer.Serialize(priv_key,
                                                             key_net_ver,
                                                             depth,
                                                             fprint,
                                                             index,
                                                             chain)
        self.m_coin_class = coin_class

    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_priv_key.Raw()

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_ser_key

    def ToWif(self,
              compr_pub_key: bool = True) -> str:
        """ Return key in WIF format.

        Args:
            compr_pub_key (bool) : True if private key corresponds to a compressed public key, false otherwise

        Returns:
            str: Key in WIF format
        """
        wif_net_ver = self.m_coin_class.WifNetVersion()

        return WifEncoder.Encode(self.Raw().ToBytes(), compr_pub_key, wif_net_ver) if wif_net_ver is not None else ""
