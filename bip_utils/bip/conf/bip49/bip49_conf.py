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

"""Module for BIP49 coins configuration."""

# Imports
from bip_utils.addr import BchP2SHAddr, P2SHAddr
from bip_utils.bip.bip32 import Bip32KeyNetVersions, Bip32Secp256k1
from bip_utils.bip.conf.common import (
    BipCoinConf, BipBitcoinCashConf, BipLitecoinConf, NOT_HARDENED_DEF_PATH
)
from bip_utils.coin_conf import (
    BitcoinConf, BitcoinCashConf, BitcoinSvConf, DashConf, DogecoinConf, LitecoinConf, ZcashConf
)


# Bitcoin key net version for main net (ypub / yprv)
_BIP49_BTC_KEY_NET_VER_MAIN: Bip32KeyNetVersions = Bip32KeyNetVersions(b"\x04\x9d\x7c\xb2",
                                                                       b"\x04\x9d\x78\x78")
# Bitcoin key net version for test net (upub / uprv)
_BIP49_BTC_KEY_NET_VER_TEST: Bip32KeyNetVersions = Bip32KeyNetVersions(b"\x04\x4a\x52\x62",
                                                                       b"\x04\x4a\x4e\x28")

# Configuration for Bitcoin main net
Bip49BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_MN,
    coin_idx=0,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": BitcoinConf.P2SH_NET_VER_MN},
)
# Configuration for Bitcoin test net
Bip49BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": BitcoinConf.P2SH_NET_VER_TN},
)

# Configuration for Bitcoin Cash main net
Bip49BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=BitcoinCashConf.COIN_NAME_MN,
    coin_idx=145,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinCashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=BchP2SHAddr,
    addr_params={
        "std": {
            "net_ver": BitcoinCashConf.P2SH_STD_NET_VER_MN,
            "hrp": BitcoinCashConf.P2SH_STD_HRP_MN,
        },
        "legacy": {
            "net_ver": BitcoinCashConf.P2SH_LEGACY_NET_VER_MN,
        }
    },
    addr_cls_legacy=P2SHAddr,
)
# Configuration for Bitcoin Cash test net
Bip49BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=BitcoinCashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinCashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=BchP2SHAddr,
    addr_params={
        "std": {
            "net_ver": BitcoinCashConf.P2SH_STD_NET_VER_TN,
            "hrp": BitcoinCashConf.P2SH_STD_HRP_TN,
        },
        "legacy": {
            "net_ver": BitcoinCashConf.P2SH_LEGACY_NET_VER_TN,
        }
    },
    addr_cls_legacy=P2SHAddr,
)

# Configuration for BitcoinSV main net
Bip49BitcoinSvMainNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinSvConf.COIN_NAME_MN,
    coin_idx=236,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinSvConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": BitcoinSvConf.P2SH_NET_VER_MN},
)
# Configuration for BitcoinSV test net
Bip49BitcoinSvTestNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinSvConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinSvConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": BitcoinSvConf.P2SH_NET_VER_TN},
)

# Configuration for Dash main net
Bip49DashMainNet: BipCoinConf = BipCoinConf(
    coin_name=DashConf.COIN_NAME_MN,
    coin_idx=5,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=DashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": DashConf.P2SH_NET_VER_MN},
)
# Configuration for Dash test net
Bip49DashTestNet: BipCoinConf = BipCoinConf(
    coin_name=DashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=DashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": DashConf.P2SH_NET_VER_TN},
)

# Configuration for Dogecoin main net
Bip49DogecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=DogecoinConf.COIN_NAME_MN,
    coin_idx=3,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x02\xfa\xca\xfd",
                                    b"\x02\xfa\xc3\x98"),   # dgub / dgpv
    wif_net_ver=DogecoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": DogecoinConf.P2SH_NET_VER_MN},
)
# Configuration for Dogecoin test net
Bip49DogecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=DogecoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x32\xa9\xa8",
                                    b"\x04\x32\xa2\x43"),   # tgub / tgpv
    wif_net_ver=DogecoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": DogecoinConf.P2SH_NET_VER_TN},
)

# Configuration for Litecoin main net
Bip49LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=LitecoinConf.COIN_NAME_MN,
    coin_idx=2,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    alt_key_net_ver=Bip32KeyNetVersions(b"\x01\xb2\x6e\xf6",
                                        b"\x01\xb2\x67\x92"),   # Mtpv / Mtub
    wif_net_ver=LitecoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={
        "std_net_ver": LitecoinConf.P2SH_STD_NET_VER_MN,
        "depr_net_ver": LitecoinConf.P2SH_DEPR_NET_VER_MN,
    },
)
# Configuration for Litecoin test net
Bip49LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=LitecoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                    b"\x04\x36\xef\x7d"),       # ttub / ttpv
    alt_key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                        b"\x04\x36\xef\x7d"),   # ttub / ttpv
    wif_net_ver=LitecoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={
        "std_net_ver": LitecoinConf.P2SH_STD_NET_VER_TN,
        "depr_net_ver": LitecoinConf.P2SH_DEPR_NET_VER_TN,
    },
)

# Configuration for Zcash main net
Bip49ZcashMainNet: BipCoinConf = BipCoinConf(
    coin_name=ZcashConf.COIN_NAME_MN,
    coin_idx=133,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=ZcashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": ZcashConf.P2SH_NET_VER_MN},
)
# Configuration for Zcash test net
Bip49ZcashTestNet: BipCoinConf = BipCoinConf(
    coin_name=ZcashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=ZcashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2SHAddr,
    addr_params={"net_ver": ZcashConf.P2SH_NET_VER_TN},
)
