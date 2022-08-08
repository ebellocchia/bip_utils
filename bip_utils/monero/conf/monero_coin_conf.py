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

"""Module with helper class for Monero coins configuration handling."""

# Imports
from __future__ import annotations

from typing import Dict

from bip_utils.coin_conf import CoinConf
from bip_utils.utils.conf import CoinNames as UtilsCoinNames


class MoneroCoinConf:
    """Monero coin configuration class."""

    m_coin_names: UtilsCoinNames
    m_addr_net_ver: bytes
    m_int_addr_net_ver: bytes
    m_subaddr_net_ver: bytes
    m_addr_params: Dict[str, bytes]

    @classmethod
    def FromCoinConf(cls,
                     coin_conf: CoinConf) -> MoneroCoinConf:
        """
        Construct class.

        Args:
            coin_conf (CoinConf object): Generic coin configuration object

        Returns:
            MoneroCoinConf object: MoneroCoinConf object
        """
        return cls(coin_names=coin_conf.CoinNames(),
                   addr_net_ver=coin_conf.ParamByKey("addr_net_ver"),
                   int_addr_net_ver=coin_conf.ParamByKey("addr_int_net_ver"),
                   subaddr_net_ver=coin_conf.ParamByKey("subaddr_net_ver"))

    def __init__(self,
                 coin_names: UtilsCoinNames,
                 addr_net_ver: bytes,
                 int_addr_net_ver: bytes,
                 subaddr_net_ver: bytes) -> None:
        """
        Construct class.

        Args:
            coin_names (CoinNames object): Coin names
            addr_net_ver (bytes)         : Address net version
            int_addr_net_ver (bytes)     : Integrated address net version
            subaddr_net_ver (bytes)      : Subaddress net version
        """
        self.m_coin_names = coin_names
        self.m_addr_net_ver = addr_net_ver
        self.m_int_addr_net_ver = int_addr_net_ver
        self.m_subaddr_net_ver = subaddr_net_ver

    def CoinNames(self) -> UtilsCoinNames:
        """
        Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_names

    def AddrNetVersion(self) -> bytes:
        """
        Get address net version.

        Returns:
            bytes: Address net version
        """
        return self.m_addr_net_ver

    def IntegratedAddrNetVersion(self) -> bytes:
        """
        Get integrated address net version.

        Returns:
            bytes: Address net version
        """
        return self.m_int_addr_net_ver

    def SubaddrNetVersion(self) -> bytes:
        """
        Get subaddress net version.

        Returns:
            bytes: Subaddress net version
        """
        return self.m_subaddr_net_ver
