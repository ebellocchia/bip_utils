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

"""Module with helper class for Substrate coins configuration handling."""

# Imports
from __future__ import annotations

from typing import Dict

from bip_utils.coin_conf import CoinConf
from bip_utils.utils.conf import CoinNames as UtilsCoinNames


class SubstrateCoinConf:
    """Substrate coin configuration class."""

    m_coin_names: UtilsCoinNames
    m_ss58_format: int
    m_addr_params: Dict[str, int]

    @classmethod
    def FromCoinConf(cls,
                     coin_conf: CoinConf) -> SubstrateCoinConf:
        """
        Construct class.

        Args:
            coin_conf (CoinConf object): Generic coin configuration object

        Returns:
            SubstrateCoinConf object: SubstrateCoinConf object
        """
        return cls(coin_names=coin_conf.CoinNames(),
                   ss58_format=coin_conf.ParamByKey("addr_ss58_format"))

    def __init__(self,
                 coin_names: UtilsCoinNames,
                 ss58_format: int) -> None:
        """
        Construct class.

        Args:
            coin_names (CoinNames object): Coin names
            ss58_format (int)            : SS58 format
        """
        self.m_coin_names = coin_names
        self.m_ss58_format = ss58_format
        self.m_addr_params = {"ss58_format": ss58_format}

    def CoinNames(self) -> UtilsCoinNames:
        """
        Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_names

    def SS58Format(self) -> int:
        """
        Get SS58 format.

        Returns:
            int: SS58 format
        """
        return self.m_ss58_format

    def AddrParams(self) -> Dict[str, int]:
        """
        Get the address parameters.

        Returns:
            dict: Address parameters
        """
        return self.m_addr_params
