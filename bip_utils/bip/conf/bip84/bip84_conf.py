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
from bip_utils.addr import P2WPKHAddr
from bip_utils.bip.bip32 import Bip32KeyNetVersions, Bip32Secp256k1
from bip_utils.bip.conf.common import *
from bip_utils.coin_conf import BitcoinConf, LitecoinConf


# Bitcoin key net version (zpub / zprv)
_BIP84_BTC_KEY_NET_VER: Bip32KeyNetVersions = Bip32KeyNetVersions(b"\x04\xb2\x47\x46",
                                                                  b"\x04\xb2\x43\x0c")

# Configuration for Bitcoin main net
Bip84BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_MN,
    coin_idx=0,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP84_BTC_KEY_NET_VER,
    wif_net_ver=BitcoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKHAddr,
    addr_params={"hrp": BitcoinConf.P2WPKH_HRP_MN, "wit_ver": BitcoinConf.P2WPKH_WIT_VER_MN},
)
# Configuration for Bitcoin test net
Bip84BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x5f\x1c\xf6",
                                    b"\x04\x5f\x18\xbc"),   # vpub / vprv
    wif_net_ver=BitcoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKHAddr,
    addr_params={"hrp": BitcoinConf.P2WPKH_HRP_TN, "wit_ver": BitcoinConf.P2WPKH_WIT_VER_TN},
)

# Configuration for Litecoin main net
Bip84LitecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=LitecoinConf.COIN_NAME_MN,
    coin_idx=2,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP84_BTC_KEY_NET_VER,
    wif_net_ver=LitecoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKHAddr,
    addr_params={"hrp": LitecoinConf.P2WPKH_HRP_MN, "wit_ver": LitecoinConf.P2WPKH_WIT_VER_MN},
)
# Configuration for Litecoin test net
Bip84LitecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=LitecoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                    b"\x04\x36\xef\x7d"),   # ttub / ttpv
    wif_net_ver=LitecoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKHAddr,
    addr_params={"hrp": LitecoinConf.P2WPKH_HRP_TN, "wit_ver": LitecoinConf.P2WPKH_WIT_VER_TN},
)
