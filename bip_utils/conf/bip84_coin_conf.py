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
from bip_utils.conf.bip_coin_conf_enum import AddrTypes, Bip32Types
from bip_utils.conf.bip_coin_conf_common import *
from bip_utils.conf.bip_coin_conf_helper import CoinNames, KeyNetVersions
from bip_utils.conf.bip_coin_conf import BipCoinConf


# Bitcoin key net version (zpub / zprv)
BIP84_BTC_KEY_NET_VER: KeyNetVersions = KeyNetVersions(b"04b24746", b"04b2430c")

# Configuration for Bitcoin main net
Bip84BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin", "BTC"),
    coin_idx=0,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP84_BTC_KEY_NET_VER,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": "bc", "wit_ver": 0},
    addr_type=AddrTypes.P2WPKH)
# Configuration for Bitcoin test net
Bip84BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin TestNet", "BTC"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"045f1cf6", b"045f18bc"),   # vpub / vprv
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": "tb", "wit_ver": 0},
    addr_type=AddrTypes.P2WPKH)

# Configuration for Litecoin main net
Bip84LitecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Litecoin", "LTC"),
    coin_idx=2,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP84_BTC_KEY_NET_VER,
    wif_net_ver=b"\xb0",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": "ltc", "wit_ver": 0},
    addr_type=AddrTypes.P2WPKH)
# Configuration for Litecoin test net
Bip84LitecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Litecoin TestNet", "LTC"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"0436f6e1", b"0436ef7d"),   # ttub / ttpv
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": "tltc", "wit_ver": 0},
    addr_type=AddrTypes.P2WPKH)
