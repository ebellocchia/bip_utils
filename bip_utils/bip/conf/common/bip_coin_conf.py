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

"""Module with helper class for generic BIP coins configuration handling."""

# Imports
from typing import Any, Dict, Optional, Type
from bip_utils.addr import IAddrEncoder
from bip_utils.bip.bip32 import Bip32KeyNetVersions, Bip32Base, Bip32PublicKey
from bip_utils.utils.conf import CoinNames as UtilsCoinNames


class BipCoinConfConst:
    """Class container for Bip coin configuration class constants."""

    # Call prefix
    CALL_PREFIX: str = "call:"


class BipCoinConf:
    """Bip coin configuration class."""

    m_coin_names: UtilsCoinNames
    m_coin_idx: int
    m_is_testnet: bool
    m_def_path: str
    m_key_net_ver: Bip32KeyNetVersions
    m_wif_net_ver: Optional[bytes]
    m_bip32_cls: Type[Bip32Base]
    m_addr_params: Dict[str, Any]
    m_addr_cls: Type[IAddrEncoder]

    def __init__(self,
                 coin_names: UtilsCoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: Bip32KeyNetVersions,
                 wif_net_ver: Optional[bytes],
                 bip32_cls: Type[Bip32Base],
                 addr_cls: Type[IAddrEncoder],
                 addr_params: Dict[str, Any]) -> None:
        """
        Construct class.

        Args:
            coin_names (CoinNames object)           : Coin names
            coin_idx (int)                          : Coin index
            is_testnet (bool)                       : Test net flag
            def_path (str)                          : Default path
            key_net_ver (Bip32KeyNetVersions object): Key net versions
            wif_net_ver (bytes)                     : WIF net version, None if not supported
            bip32_cls (Bip32Base class)             : Bip32 class
            addr_params (dict)                      : Address parameters
            addr_cls (IAddrEncoder class)           : Address class
        """
        self.m_coin_names = coin_names
        self.m_coin_idx = coin_idx
        self.m_is_testnet = is_testnet
        self.m_def_path = def_path
        self.m_key_net_ver = key_net_ver
        self.m_wif_net_ver = wif_net_ver
        self.m_bip32_cls = bip32_cls
        self.m_addr_params = addr_params
        self.m_addr_cls = addr_cls

    def CoinNames(self) -> UtilsCoinNames:
        """
        Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_names

    def CoinIndex(self) -> int:
        """
        Get coin index.

        Returns:
            int: Coin index
        """
        return self.m_coin_idx

    def IsTestNet(self) -> bool:
        """
        Get if test net.

        Returns:
            bool: True if test net, false otherwise
        """
        return self.m_is_testnet

    def DefaultPath(self) -> str:
        """
        Get the default derivation path.

        Returns:
            str: Default derivation path
        """
        return self.m_def_path

    def KeyNetVersions(self) -> Bip32KeyNetVersions:
        """
        Get key net versions.

        Returns:
            Bip32KeyNetVersions object: Bip32KeyNetVersions object
        """
        return self.m_key_net_ver

    def WifNetVersion(self) -> Optional[bytes]:
        """
        Get WIF net version.

        Returns:
            bytes: WIF net version bytes
            None: If WIF is not supported
        """
        return self.m_wif_net_ver

    def Bip32Class(self) -> Type[Bip32Base]:
        """
        Get the Bip32 class.

        Returns:
            Bip32Base class: Bip32Base class
        """
        return self.m_bip32_cls

    def AddrParams(self) -> Dict[str, Any]:
        """
        Get the address parameters.

        Returns:
            dict: Address parameters
        """
        return self.m_addr_params

    def AddrParamsResolveCalls(self,
                               pub_key: Bip32PublicKey) -> Dict[str, Any]:
        """
        Resolve function calls and get the address parameters.

        Returns:
            dict: Address parameters
        """

        # Just use the internal object if nothing to be resolved
        if not any(
            [isinstance(param_val, str) and param_val.startswith(BipCoinConfConst.CALL_PREFIX)
             for param_val in self.m_addr_params.values()]
        ):
            return self.AddrParams()

        resolved_params = {}
        for param_name, param_val in self.m_addr_params.items():
            if isinstance(param_val, str) and param_val.startswith(BipCoinConfConst.CALL_PREFIX):
                fct_calls = param_val.replace(BipCoinConfConst.CALL_PREFIX, "").split(",")
                # Resolve function calls
                obj = pub_key
                for fct_call in fct_calls:
                    obj = getattr(obj, fct_call)()
                resolved_params[param_name] = obj
            else:
                resolved_params[param_name] = param_val

        return resolved_params

    def AddrClass(self) -> Type[IAddrEncoder]:
        """
        Get the address class.

        Returns:
            IAddrEncoder class: Address class
        """
        return self.m_addr_cls
