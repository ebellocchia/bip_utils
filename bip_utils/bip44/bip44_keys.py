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
from bip_utils.bip32 import Bip32KeyData, Bip32PublicKey, Bip32PrivateKey
from bip_utils.conf import AddrTypes, BipCoinConf
from bip_utils.ecc import EllipticCurveTypes, IPublicKey, IPrivateKey
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


class Bip44PublicKey(Bip32PublicKey):
    """ BIP44 public key class.
    It extends Bip32PublicKey by adding the possibility to compute the address
    from the coin type.
    """

    def __init__(self,
                 pub_key: IPublicKey,
                 key_data: Bip32KeyData,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            pub_key (IPublicKey object)   : Key object
            key_data (Bip32KeyData object): Key data
            coin_conf (BipCoinConf object): BipCoinConf object
        """
        super().__init__(pub_key, key_data)

        self.m_coin_conf = coin_conf

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
        addr_cls = Bip44KeysConst.ADDR_TYPE_TO_CLASS[addr_type]

        # P2PKH, P2SH
        if addr_type in (AddrTypes.P2PKH, AddrTypes.P2SH):
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["net_ver"])
        # P2WPKH
        elif addr_type == AddrTypes.P2WPKH:
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["wit_ver"], addr_conf["net_ver"])
        # BCH P2PKH and P2SH
        elif addr_type in (AddrTypes.P2PKH_BCH, AddrTypes.P2SH_BCH):
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["hrp"], addr_conf["net_ver"])
        # Atom
        elif addr_type == AddrTypes.ATOM:
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["hrp"])
        # Substrate
        elif addr_type == AddrTypes.SUBSTRATE:
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["ss58_ver"])
        # NEO
        elif addr_type == AddrTypes.NEO:
            return addr_cls.EncodeKey(self.m_pub_key, addr_conf["ver"])
        # Others
        else:
            return addr_cls.EncodeKey(self.m_pub_key)


class Bip44PrivateKey(Bip32PrivateKey):
    """ BIP44 private key class.
    It extends Bip32PrivateKey by adding the possibility to compute the WIF
    from the coin type.
    """

    def __init__(self,
                 priv_key: IPrivateKey,
                 key_data: Bip32KeyData,
                 coin_conf: BipCoinConf) -> None:
        """ Construct class.

        Args:
            priv_key (IPrivateKey object) : Key object
            key_data (Bip32KeyData object): Key data
            coin_conf (BipCoinConf object): BipCoinConf object
        """
        super().__init__(priv_key, key_data)

        self.m_coin_conf = coin_conf

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

        return WifEncoder.Encode(self.Raw().ToBytes(), compr_pub_key, wif_net_ver) if wif_net_ver is not None else ""
