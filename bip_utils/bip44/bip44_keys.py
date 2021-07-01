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
from typing import Any, Dict
from bip_utils.addr import *
from bip_utils.bip32 import Bip32PublicKey, Bip32PrivateKey
from bip_utils.conf import AddrTypes, BipCoinConf
from bip_utils.ecc import KeyBytes
from bip_utils.wif import WifEncoder


class Bip44KeysConst:
    """ Class container for BIP44 keys constants. """

    # Address type to class
    ADDR_TYPE_TO_CLASS: Dict[AddrTypes, Any] = {
        AddrTypes.ALGO: AlgoAddr,
        AddrTypes.AVAX_P: AvaxPChainAddr,
        AddrTypes.AVAX_X: AvaxXChainAddr,
        AddrTypes.ATOM: AtomAddr,
        AddrTypes.EGLD: EgldAddr,
        AddrTypes.ETH: EthAddr,
        AddrTypes.FIL: FilAddr,
        AddrTypes.NANO: NanoAddr,
        AddrTypes.NEO: NeoAddr,
        AddrTypes.OKEX: OkexAddr,
        AddrTypes.ONE: OneAddr,
        AddrTypes.P2PKH: P2PKHAddr,
        AddrTypes.P2PKH_BCH: BchP2PKHAddr,
        AddrTypes.P2SH: P2SHAddr,
        AddrTypes.P2SH_BCH: BchP2SHAddr,
        AddrTypes.P2WPKH: P2WPKHAddr,
        AddrTypes.SOL: SolAddr,
        AddrTypes.SUBSTRATE: SubstrateEd25519Addr,
        AddrTypes.TRX: TrxAddr,
        AddrTypes.XLM: XlmAddr,
        AddrTypes.XRP: XrpAddr,
        AddrTypes.XTZ: XtzAddr,
        AddrTypes.ZIL: ZilAddr,
    }


class Bip44PublicKey:
    """ BIP44 public key class.
    It contains Bip32PublicKey and add the possibility to compute the address
    from the coin type.
    """

    def __init__(self,
                 pub_key: Bip32PublicKey,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            pub_key (Bip32PublicKey object): Bip32PublicKey object
            coin_conf (BipCoinConf object) : BipCoinConf object
        """
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

    @lru_cache()
    def ToAddress(self) -> str:
        """ Return address correspondent to the public key.

        Returns:
            str: Address string
        """
        return self.__ComputeAddress()

    def __ComputeAddress(self) -> str:
        """ Compute address.

        Returns:
            str: Address string
        """
        addr_conf = self.m_coin_conf.AddrConf()
        addr_type = self.m_coin_conf.AddrType()
        pub_key_obj = self.Bip32Key().KeyObject()

        addr_cls = Bip44KeysConst.ADDR_TYPE_TO_CLASS[addr_type]

        # P2PKH, P2SH
        if addr_type in (AddrTypes.P2PKH, AddrTypes.P2SH):
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["net_ver"])
        # P2WPKH
        elif addr_type == AddrTypes.P2WPKH:
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["wit_ver"], addr_conf["net_ver"])
        # BCH P2PKH and P2SH
        elif addr_type in (AddrTypes.P2PKH_BCH, AddrTypes.P2SH_BCH):
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["hrp"], addr_conf["net_ver"])
        # Atom
        elif addr_type == AddrTypes.ATOM:
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["hrp"])
        # Substrate
        elif addr_type == AddrTypes.SUBSTRATE:
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["ss58_ver"])
        # NEO
        elif addr_type == AddrTypes.NEO:
            return addr_cls.EncodeKey(pub_key_obj, addr_conf["ver"])
        # Others
        else:
            return addr_cls.EncodeKey(pub_key_obj)


class Bip44PrivateKey:
    """ BIP44 private key class.
    It contains Bip32PrivateKey and add the possibility to compute the WIF
    from the coin type.
    """

    def __init__(self,
                 priv_key: Bip32PrivateKey,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            priv_key (Bip32PrivateKey object): Bip32PrivateKey object
            coin_conf (BipCoinConf object)   : BipCoinConf object
        """
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

    def Raw(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
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

        return WifEncoder.Encode(self.m_priv_key.Raw().ToBytes(), compr_pub_key, wif_net_ver) if wif_net_ver is not None else ""
