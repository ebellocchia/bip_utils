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
from functools import lru_cache
from bip_utils.addr import *
from bip_utils.bip.bip32 import Bip32PublicKey, Bip32PrivateKey
from bip_utils.bip.conf.common import BipCoinConf
from bip_utils.utils.misc import DataBytes
from bip_utils.wif import WifEncoder


class Bip44PublicKey:
    """ BIP44 public key class.
    It contains Bip32PublicKey and add the possibility to compute the address
    from the coin type.
    """

    m_pub_key: Bip32PublicKey
    m_coin_conf: BipCoinConf

    def __init__(self,
                 pub_key: Bip32PublicKey,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            pub_key (Bip32PublicKey object): Bip32PublicKey object
            coin_conf (BipCoinConf object) : BipCoinConf object
        """
        if pub_key.CurveType() != coin_conf.Bip32Class().CurveType():
            raise ValueError(
                f"The public key ({pub_key.CurveType()}) elliptic curve shall match"
                f"the coin configuration one ({coin_conf.Bip32Class().CurveType()})"
            )

        self.m_pub_key = pub_key
        self.m_coin_conf = coin_conf

    def Bip32Key(self) -> Bip32PublicKey:
        """ Return the BIP32 key object.

        Returns:
            Bip32PublicKey object: BIP32 key object
        """
        return self.m_pub_key

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_pub_key.ToExtended()

    def RawCompressed(self) -> DataBytes:
        """ Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawCompressed()

    def RawUncompressed(self) -> DataBytes:
        """ Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawUncompressed()

    @lru_cache()
    def ToAddress(self) -> str:
        """ Return the address correspondent to the public key.

        Returns:
            str: Address string
        """
        return self.__ComputeAddress()

    def __ComputeAddress(self) -> str:
        """ Compute address.

        Returns:
            str: Address string
        """
        addr_params = self.m_coin_conf.AddrParams()
        addr_cls = self.m_coin_conf.AddrClass()
        pub_key_obj = self.Bip32Key().KeyObject()

        # Exception for Monero
        if addr_cls is XmrAddr:
            raise ValueError("Use the Monero class to get Monero addresses")

        return addr_cls.EncodeKey(pub_key_obj, **addr_params)


class Bip44PrivateKey:
    """ BIP44 private key class.
    It contains Bip32PrivateKey and add the possibility to compute the WIF
    from the coin type.
    """

    m_priv_key: Bip32PrivateKey
    m_coin_conf: BipCoinConf

    def __init__(self,
                 priv_key: Bip32PrivateKey,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            priv_key (Bip32PrivateKey object): Bip32PrivateKey object
            coin_conf (BipCoinConf object)   : BipCoinConf object
        """
        if priv_key.CurveType() != coin_conf.Bip32Class().CurveType():
            raise ValueError(
                f"The private key ({pub_key.CurveType()}) elliptic curve shall match"
                f"the coin configuration one ({coin_conf.Bip32Class().CurveType()})"
            )

        self.m_priv_key = priv_key
        self.m_coin_conf = coin_conf

    def Bip32Key(self) -> Bip32PrivateKey:
        """ Return the BIP32 key object.

        Returns:
            Bip32PublicKey object: BIP32 key object
        """
        return self.m_priv_key

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_priv_key.ToExtended()

    def Raw(self) -> DataBytes:
        """ Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_priv_key.Raw()

    @lru_cache()
    def ToWif(self,
              compr_pub_key: bool = True) -> str:
        """ Return key in WIF format.

        Args:
            compr_pub_key (bool) : True if private key corresponds to a compressed public key, false otherwise

        Returns:
            str: Key in WIF format
        """
        wif_net_ver = self.m_coin_conf.WifNetVersion()

        return (WifEncoder.Encode(self.m_priv_key.Raw().ToBytes(), wif_net_ver, compr_pub_key)
                if wif_net_ver is not None
                else "")
