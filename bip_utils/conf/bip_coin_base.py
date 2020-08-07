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
from bip_utils.addr import P2PKH, P2SH, P2WPKH, AtomAddr, EthAddr, TrxAddr, XrpAddr


class BipCoinBase:
    """ Bip coin base class. It's the base class for BipCoin classes (e.g. Bip44Coin, Bip49Coin).
    It basically wraps the coin configuration allowing to get through methods.
    """

    def __init__(self, coin_conf, key_net_ver, is_testnet, addr_fct):
        """ Construct class.

        Args:
            coin_conf (class)                  : Coin configuration class
            key_net_ver (KeyNetVersions object): Key net versions
            is_testnet (bool)                  : True if test net, false otherwise
            addr_fct (class)                   : Address class
        """
        self.m_coin_conf   = coin_conf
        self.m_key_net_ver = key_net_ver
        self.m_is_testnet  = is_testnet
        self.m_addr_fct    = addr_fct

    def KeyNetVersions(self):
        """ Get key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """
        return self.m_key_net_ver.Main() if not self.m_is_testnet else self.m_key_net_ver.Test()

    def WifNetVersion(self):
        """ Get WIF net version.

        Returns:
            bytes: WIF net version bytes
            None: If WIF is not supported
        """
        return self.m_coin_conf.WIF_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.WIF_NET_VER.Test()

    def IsTestNet(self):
        """ Get if test net

        Returns:
            bool: True if test net, false otherwise
        """
        return self.m_is_testnet

    def CoinNames(self):
        """ Get coin names.

        Returns:
            CoinNames object: CoinNames object
        """
        return self.m_coin_conf.NAMES if not self.m_is_testnet else self.m_coin_conf.TEST_NAMES

    def ComputeAddress(self, pub_key):
        """ Compute address from public key.

        Args:
            pub_key (BipPublicKey object): BipPublicKey object

        Returns:
            str: Address string
        """

        # This if-else can be avoided by creating a child class for each address, but I leave it here for now since
        # there are few different address functions.

        # P2PKH
        if self.m_addr_fct is P2PKH:
            addr_ver = self.m_coin_conf.P2PKH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.P2PKH_NET_VER.Test()
            return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)
        # P2SH
        elif self.m_addr_fct is P2SH:
            addr_ver = self.m_coin_conf.P2SH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.P2SH_NET_VER.Test()
            return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)
        # P2WPKH
        elif self.m_addr_fct is P2WPKH:
            addr_ver = self.m_coin_conf.P2WPKH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.P2WPKH_NET_VER.Test()
            return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)
        # EthAddr
        elif self.m_addr_fct is EthAddr or self.m_addr_fct is TrxAddr:
            return self.m_addr_fct.ToAddress(pub_key.RawUncompressed().ToBytes())
        # XrpAddr
        elif self.m_addr_fct is XrpAddr:
            return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes())
        # AtomAddr
        elif self.m_addr_fct is AtomAddr:
            return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes(), self.m_coin_conf.ADDR_HRP.Main())
        else:
            raise RuntimeError("Invalid address class")
