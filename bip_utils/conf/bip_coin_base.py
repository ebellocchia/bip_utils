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
from bip_utils.addr import (
    P2PKH, P2SH, P2WPKH, AtomAddr, AvaxPChainAddr, AvaxXChainAddr,
    EthAddr, OkexAddr, OneAddr, SolAddr, TrxAddr, XrpAddr
)
from bip_utils.bip32 import Bip32Base
from bip_utils.ecc import IPublicKey
from bip_utils.conf.bip_coin_conf_helper import *


class BipCoinBase:
    """ Bip coin base class. It's the base class for BipCoin classes (e.g. Bip44Coin, Bip49Coin).
    It basically wraps the coin configuration allowing to get it through methods.
    """

    def __init__(self,
                 coin_conf: Any,
                 key_net_ver: NetVersions,
                 is_testnet: bool,
                 bip32_cls: Type[Bip32Base],
                 addr_cls: Any) -> None:
        """ Construct class.

        Args:
            coin_conf (class)                  : Coin configuration class
            key_net_ver (KeyNetVersions object): Key net versions
            is_testnet (bool)                  : True if test net, false otherwise
            bip32_cls (Bip32Base class)        : Bip32 class
            addr_cls (class)                   : Address class
        """
        self.m_coin_conf = coin_conf
        self.m_key_net_ver = key_net_ver
        self.m_is_testnet = is_testnet
        self.m_bip32_cls = bip32_cls
        self.m_addr_cls = addr_cls

    def Bip32Class(self) -> Type[Bip32Base]:
        """ Get the Bip32 class.

        Returns:
            Bip32Base: Bip32 class
        """
        return self.m_bip32_cls

    def KeyNetVersions(self) -> KeyNetVersions:
        """ Get key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """
        return self.m_key_net_ver.Main() if not self.m_is_testnet else self.m_key_net_ver.Test()

    def WifNetVersion(self) -> bytes:
        """ Get WIF net version.

        Returns:
            bytes: WIF net version bytes
            None: If WIF is not supported
        """
        return self.m_coin_conf.WIF_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.WIF_NET_VER.Test()

    def IsTestNet(self) -> bool:
        """ Get if test net

        Returns:
            bool: True if test net, false otherwise
        """
        return self.m_is_testnet

    def CoinNames(self) -> CoinNames:
        """ Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_conf.NAMES if not self.m_is_testnet else self.m_coin_conf.TEST_NAMES

    def ComputeAddress(self,
                       pub_key: IPublicKey) -> str:
        """ Compute address from public key.

        Args:
            pub_key (IPublicKey object): IPublicKey object

        Returns:
            str: Address string

        Raises:
            RuntimeError: If the configured address class is not valid
        """

        # This if-else can be avoided by creating a child class for each address, but I leave it here for now since
        # there are few different address functions.

        # P2PKH
        if self.m_addr_cls is P2PKH:
            addr_ver = (self.m_coin_conf.P2PKH_NET_VER.Main()
                        if not self.m_is_testnet
                        else self.m_coin_conf.P2PKH_NET_VER.Test())
            return self.m_addr_cls.ToAddress(pub_key, addr_ver)
        # P2SH
        elif self.m_addr_cls is P2SH:
            addr_ver = (self.m_coin_conf.P2SH_NET_VER.Main()
                        if not self.m_is_testnet
                        else self.m_coin_conf.P2SH_NET_VER.Test())
            return self.m_addr_cls.ToAddress(pub_key, addr_ver)
        # P2WPKH
        elif self.m_addr_cls is P2WPKH:
            addr_ver = (self.m_coin_conf.P2WPKH_NET_VER.Main()
                        if not self.m_is_testnet
                        else self.m_coin_conf.P2WPKH_NET_VER.Test())
            return self.m_addr_cls.ToAddress(pub_key, addr_ver)
        # AtomAddr
        elif self.m_addr_cls is AtomAddr:
            return self.m_addr_cls.ToAddress(pub_key, self.m_coin_conf.ADDR_HRP.Main())
        # Others
        elif self.m_addr_cls in [AvaxPChainAddr, AvaxXChainAddr, EthAddr, OkexAddr, OneAddr, SolAddr, TrxAddr, XrpAddr]:
            return self.m_addr_cls.ToAddress(pub_key)
        # Invalid class
        else:
            raise RuntimeError("Invalid address class")
