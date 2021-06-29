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
from bip_utils.conf.bip_coin_conf import BipCoinConf, BipBitcoinCashConf, BipLitecoinConf


# Bitcoin key net version for main net (ypub / yprv)
BIP49_BTC_KEY_NET_VER_MAIN: KeyNetVersions = KeyNetVersions(b"049d7cb2", b"049d7878")
# Bitcoin key net version for test net (upub / uprv)
BIP49_BTC_KEY_NET_VER_TEST: KeyNetVersions = KeyNetVersions(b"044a5262", b"044a4e28")
# Bitcoin P2SH net version for main net
BIP49_BTC_P2SH_NET_VER_MAIN: bytes = b"\x05"
# Bitcoin P2SH net version for test net
BIP49_BTC_P2SH_NET_VER_TEST: bytes = b"\xc4"

# Configuration for Bitcoin main net
Bip49BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin", "BTC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP49_BTC_P2SH_NET_VER_MAIN},
    addr_type=AddrTypes.P2SH)
# Configuration for Bitcoin test net
Bip49BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin TestNet", "BTC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\xc4"},
    addr_type=AddrTypes.P2SH)

# Configuration for Bitcoin Cash main net
Bip49BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash", "BCH"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x08", "std_hrp": "bitcoincash", "legacy_net_ver":  BIP49_BTC_P2SH_NET_VER_MAIN},
    addr_type=AddrTypes.P2SH_BCH,
    addr_type_legacy=AddrTypes.P2SH)
# Configuration for Bitcoin Cash test net
Bip49BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash TestNet", "BCH"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x08", "std_hrp": "bchtest", "legacy_net_ver":  BIP49_BTC_P2SH_NET_VER_TEST},
    addr_type=AddrTypes.P2SH_BCH,
    addr_type_legacy=AddrTypes.P2SH)

# Configuration for BitcoinSV main net
Bip49BitcoinSvMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV", "BSV"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP49_BTC_P2SH_NET_VER_MAIN},
    addr_type=AddrTypes.P2SH)
# Configuration for BitcoinSV test net
Bip49BitcoinSvTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV TestNet", "BSV"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP49_BTC_P2SH_NET_VER_TEST},
    addr_type=AddrTypes.P2SH)

# Configuration for Dash main net
Bip49DashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash", "DASH"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=b"\xcc",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x10"},
    addr_type=AddrTypes.P2SH)
# Configuration for Dash test net
Bip49DashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash TestNet", "DASH"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x13"},
    addr_type=AddrTypes.P2SH)

# Configuration for Dogecoin main net
Bip49DogecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin", "DOGE"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"02facafd", b"02fac398"),   # dgub / dgpv
    wif_net_ver=b"\x9e",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x16"},
    addr_type=AddrTypes.P2SH)
# Configuration for Dogecoin test net
Bip49DogecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin TestNet", "DOGE"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"0432a9a8", b"0432a243"),   # tgub / tgpv
    wif_net_ver=b"\xf1",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP49_BTC_P2SH_NET_VER_TEST},
    addr_type=AddrTypes.P2SH)

# Configuration for Litecoin main net
Bip49LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin", "LTC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    alt_key_net_ver=KeyNetVersions(b"01b26ef6", b"01b26792"),   # Mtpv / Mtub
    wif_net_ver=b"\xb0",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x32", "depr_net_ver": BIP49_BTC_P2SH_NET_VER_MAIN},
    addr_type=AddrTypes.P2SH)
# Configuration for Litecoin test net
Bip49LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin TestNet", "LTC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"0436f6e1", b"0436ef7d"),       # ttub / ttpv
    alt_key_net_ver=KeyNetVersions(b"0436f6e1", b"0436ef7d"),   # ttub / ttpv
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x3a", "depr_net_ver": BIP49_BTC_P2SH_NET_VER_TEST},
    addr_type=AddrTypes.P2SH)

# Configuration for Zcash main net
Bip49ZcashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash", "ZEC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x1c\xbd"},
    addr_type=AddrTypes.P2SH)
# Configuration for Zcash test net
Bip49ZcashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash TestNet", "ZEC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP49_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x1c\xba"},
    addr_type=AddrTypes.P2SH)
