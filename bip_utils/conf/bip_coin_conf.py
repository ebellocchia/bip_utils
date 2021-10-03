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
from bip_utils.conf.bip_coin_conf_enum import AddrTypes, Bip32Types
from bip_utils.conf.bip_coin_conf_helper import CoinNames, KeyNetVersions


class BipCoinConf:
    """ Bip coin configuration class. """

    def __init__(self,
                 coin_name: CoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: KeyNetVersions,
                 wif_net_ver: Optional[bytes],
                 bip32_type: Bip32Types,
                 addr_conf: Dict[str, Union[bytes, str, int]],
                 addr_type: AddrTypes) -> None:
        """ Construct class.

        Args:
            coin_name (CoinNames object)       : Coin names
            coin_idx (int)                     : Coin index
            is_testnet (bool)                  : Test net flag
            def_path (str)                     : Default path
            key_net_ver (KeyNetVersions object): Key net versions
            wif_net_ver (bytes)                : WIF net version, None if not supported
            bip32_type (Bip32Types)            : Bip32 type
            addr_conf (dict)                   : Address configuration
            addr_type (AddrTypes)              : Address type
        """
        self.m_coin_name = coin_name
        self.m_coin_idx = coin_idx
        self.m_is_testnet = is_testnet
        self.m_def_path = def_path
        self.m_key_net_ver = key_net_ver
        self.m_wif_net_ver = wif_net_ver
        self.m_bip32_type = bip32_type
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

    def KeyNetVersions(self) -> KeyNetVersions:
        """ Get key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """
        return self.m_key_net_ver

    def WifNetVersion(self) -> Optional[bytes]:
        """ Get WIF net version.

        Returns:
            bytes: WIF net version bytes
            None: If WIF is not supported
        """
        return self.m_wif_net_ver

    def Bip32Type(self) -> Bip32Types:
        """ Get the Bip32 type.

        Returns:
            Bip32Types: Bip32 type
        """
        return self.m_bip32_type

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


class BipBitcoinCashConf(BipCoinConf):
    """ Bitcoin Cash configuration class.
    It allows to return different addresses depending on the configuration.
    """

    def __init__(self,
                 coin_name: CoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: KeyNetVersions,
                 wif_net_ver: bytes,
                 bip32_type: Bip32Types,
                 addr_conf: Dict[str, Union[bytes, str, int]],
                 addr_type: AddrTypes,
                 addr_type_legacy: AddrTypes) -> None:
        """ Construct class.

        Args:
            coin_name (CoinNames object)       : Coin names
            coin_idx (int)                     : Coin index
            is_testnet (bool)                  : Test net flag
            def_path (str)                     : Default path
            key_net_ver (KeyNetVersions object): Key net versions
            wif_net_ver (bytes)                : WIF net version
            bip32_type (Bip32Types)            : Bip32 type
            addr_conf (dict)                   : Address configuration
            addr_type (AddrTypes)              : Address type
            addr_type_legacy (AddrTypes)       : Legacy ddress type
        """
        super().__init__(coin_name,
                         coin_idx,
                         is_testnet,
                         def_path,
                         key_net_ver,
                         wif_net_ver,
                         bip32_type,
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


class BipLitecoinConf(BipCoinConf):
    """ Litecoin configuration class.
    It allows to return different addresses and key net versions depending on the configuration.
    """

    def __init__(self,
                 coin_name: CoinNames,
                 coin_idx: int,
                 is_testnet: bool,
                 def_path: str,
                 key_net_ver: KeyNetVersions,
                 alt_key_net_ver: KeyNetVersions,
                 wif_net_ver: bytes,
                 bip32_type: Bip32Types,
                 addr_conf: Dict[str, Union[bytes, str, int]],
                 addr_type: AddrTypes) -> None:
        """ Construct class.

        Args:
            coin_name (CoinNames object)           : Coin names
            coin_idx (int)                         : Coin index
            is_testnet (bool)                      : Test net flag
            def_path (str)                         : Default path
            key_net_ver (KeyNetVersions object)    : Key net versions
            alt_key_net_ver (KeyNetVersions object): Key net versions (alternate)
            wif_net_ver (bytes)                    : WIF net version
            bip32_type (Bip32Types)                : Bip32 type
            addr_conf (dict)                       : Address configuration
            addr_type (AddrTypes)                  : Address type
        """
        super().__init__(coin_name,
                         coin_idx,
                         is_testnet,
                         def_path,
                         key_net_ver,
                         wif_net_ver,
                         bip32_type,
                         addr_conf,
                         addr_type)

        self.m_alt_key_net_ver = alt_key_net_ver
        self.m_use_alt_key_net_ver = False
        self.m_use_depr_addr = False

    def UseAlternateKeyNetVersions(self,
                                   value: bool) -> None:
        """ Select if use the alternate key net version.

        Args:
            value (bool): True for using alternate key net version, false for using the standard one
        """
        self.m_use_alt_key_net_ver = value

    def UseDeprecatedAddress(self,
                             value: bool) -> None:
        """ Select if use the deprecated address.

        Args:
            value (bool): True for using deprecated address, false for using the standard one
        """
        self.m_use_depr_addr = value

    def KeyNetVersions(self) -> KeyNetVersions:
        """ Get key net versions. It overrides the method in BipCoinConf.
        Litecoin overrides the method because it can have 2 different key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """

        # Get standard or alternate version depending on the configuration flag
        return self.m_alt_key_net_ver if self.m_use_alt_key_net_ver else self.m_key_net_ver

    def AddrConf(self) -> Dict[str, Union[bytes, str, int]]:
        """ Get the address configuration. It overrides the method in BipCoinConf.

        Returns:
            dict: Address configuration
        """
        return ({"net_ver": self.m_addr_conf["depr_net_ver"]}
                if self.m_use_depr_addr
                else {"net_ver": self.m_addr_conf["std_net_ver"]})
