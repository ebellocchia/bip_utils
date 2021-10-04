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
from typing import Any, Dict, Optional, Union
from bip_utils.bip.conf.common.addr_types import AddrTypes
from bip_utils.bip.bip32 import Bip32KeyNetVersions, Bip32Base
from bip_utils.utils import CoinNames


class BipCoinConf:
    """ Bip coin configuration class. """

    def __init__(self,
                 coin_name: CoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: Bip32KeyNetVersions,
                 wif_net_ver: Optional[bytes],
                 bip32_cls: Bip32Base,
                 addr_conf: Dict[str, Union[bytes, str, int]],
                 addr_type: AddrTypes) -> None:
        """ Construct class.

        Args:
            coin_name (CoinNames object)            : Coin names
            coin_idx (int)                          : Coin index
            is_testnet (bool)                       : Test net flag
            def_path (str)                          : Default path
            key_net_ver (Bip32KeyNetVersions object): Key net versions
            wif_net_ver (bytes)                     : WIF net version, None if not supported
            bip32_cls (Bip32Base object)            : Bip32 class
            addr_conf (dict)                        : Address configuration
            addr_type (AddrTypes)                   : Address type
        """
        self.m_coin_name = coin_name
        self.m_coin_idx = coin_idx
        self.m_is_testnet = is_testnet
        self.m_def_path = def_path
        self.m_key_net_ver = key_net_ver
        self.m_wif_net_ver = wif_net_ver
        self.m_bip32_cls = bip32_cls
        self.m_addr_conf = addr_conf
        self.m_addr_type = addr_type

    def CoinNames(self) -> CoinNames:
        """ Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_name

    def CoinIndex(self) -> int:
        """ Get coin index.

        Returns:
            int: Coin index
        """
        return self.m_coin_idx

    def IsTestNet(self) -> bool:
        """ Get if test net.

        Returns:
            bool: True if test net, false otherwise
        """
        return self.m_is_testnet

    def DefaultPath(self) -> str:
        """ Get the default derivation path.

        Returns:
            str: Default derivation path
        """
        return self.m_def_path

    def KeyNetVersions(self) -> Bip32KeyNetVersions:
        """ Get key net versions.

        Returns:
            Bip32KeyNetVersions object: Bip32KeyNetVersions object
        """
        return self.m_key_net_ver

    def WifNetVersion(self) -> Optional[bytes]:
        """ Get WIF net version.

        Returns:
            bytes: WIF net version bytes
            None: If WIF is not supported
        """
        return self.m_wif_net_ver

    def Bip32Class(self) -> Bip32Base:
        """ Get the Bip32 class.

        Returns:
            Bip32Base: Bip32 class
        """
        return self.m_bip32_cls

    def AddrConf(self) -> Dict[str, Union[bytes, str, int]]:
        """ Get the address configuration.

        Returns:
            dict: Address configuration
        """
        return self.m_addr_conf

    def AddrConfKey(self,
                    key: str) -> Any:
        """ Get the address configuration for the specified key.

        Args:
            key (str): Key

        Returns:
            bytes or str: Address configuration for the specified key
        """
        return self.AddrConf()[key]

    def AddrType(self) -> AddrTypes:
        """ Get the address type.

        Returns:
            AddrTypes: Address type
        """
        return self.m_addr_type
