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
from typing import Dict, Union
from bip_utils.bip.conf.common.addr_types import AddrTypes
from bip_utils.bip.conf.common.bip_coin_conf import BipCoinConf, Bip32Base
from bip_utils.bip.bip32 import Bip32KeyNetVersions
from bip_utils.utils import CoinNames


class BipBitcoinCashConf(BipCoinConf):
    """ Bitcoin Cash configuration class.
    It allows to return different addresses depending on the configuration.
    """

    def __init__(self,
                 coin_name: CoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: Bip32KeyNetVersions,
                 wif_net_ver: bytes,
                 bip32_cls: Bip32Base,
                 addr_conf: Dict[str, Union[bytes, str, int]],
                 addr_type: AddrTypes,
                 addr_type_legacy: AddrTypes) -> None:
        """ Construct class.

        Args:
            coin_name (CoinNames object)            : Coin names
            coin_idx (int)                          : Coin index
            is_testnet (bool)                       : Test net flag
            def_path (str)                          : Default path
            key_net_ver (Bip32KeyNetVersions object): Key net versions
            wif_net_ver (bytes)                     : WIF net version
            bip32_cls (Bip32Base object)            : Bip32 class
            addr_conf (dict)                        : Address configuration
            addr_type (AddrTypes)                   : Address type
            addr_type_legacy (AddrTypes)            : Legacy ddress type
        """
        super().__init__(coin_name,
                         coin_idx,
                         is_testnet,
                         def_path,
                         key_net_ver,
                         wif_net_ver,
                         bip32_cls,
                         addr_conf,
                         addr_type)

        self.m_addr_type_legacy = addr_type_legacy
        self.m_use_legacy_addr = False

    def UseLegacyAddress(self,
                         value: bool) -> None:
        """ Select if use the legacy address.

        Args:
            value (bool): True for using legacy address, false for using the standard one
        """
        self.m_use_legacy_addr = value

    def AddrType(self) -> AddrTypes:
        """ Get the address type. It overrides the method in BipCoinConf.

        Returns:
            AddrTypes: Address type
        """
        return self.m_addr_type_legacy if self.m_use_legacy_addr else self.m_addr_type

    def AddrConf(self) -> Dict[str, Union[bytes, str, int]]:
        """ Get the address configuration. It overrides the method in BipCoinConf.

        Returns:
            dict: Address configuration
        """
        return ({"net_ver": self.m_addr_conf["legacy_net_ver"]}
                if self.m_use_legacy_addr
                else {"hrp": self.m_addr_conf["std_hrp"], "net_ver": self.m_addr_conf["std_net_ver"]})
