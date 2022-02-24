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
from bip_utils.addr import BchP2SHAddrEncoder, P2SHAddrEncoder
from bip_utils.bip.bip32 import Bip32KeyNetVersions, Bip32Secp256k1
from bip_utils.bip.conf.common import (
    BipCoinConf, BipBitcoinCashConf, BipLitecoinConf, NOT_HARDENED_DEF_PATH
)
from bip_utils.coin_conf import CoinsConf


# Bitcoin key net version for main net (ypub / yprv)
_BIP49_BTC_KEY_NET_VER_MAIN: Bip32KeyNetVersions = Bip32KeyNetVersions(b"\x04\x9d\x7c\xb2",
                                                                       b"\x04\x9d\x78\x78")
# Bitcoin key net version for test net (upub / uprv)
_BIP49_BTC_KEY_NET_VER_TEST: Bip32KeyNetVersions = Bip32KeyNetVersions(b"\x04\x4a\x52\x62",
                                                                       b"\x04\x4a\x4e\x28")


class Bip49Conf:
    """Class container for Bip49 configuration."""

    # Configuration for Bitcoin main net
    BitcoinMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinMainNet.CoinNames(),
        coin_idx=0,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.BitcoinMainNet.Params("p2sh_net_ver"),
        },
    )
    # Configuration for Bitcoin test net
    BitcoinTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.BitcoinTestNet.Params("p2sh_net_ver"),
        },
    )

    # Configuration for Bitcoin Cash main net
    BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinCashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashMainNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )
    # Configuration for Bitcoin Cash test net
    BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinCashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashTestNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashTestNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashTestNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )

    # Configuration for Bitcoin Cash Simple Ledger Protocol main net
    BitcoinCashSlpMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashSlpMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinCashSlpMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashSlpMainNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashSlpMainNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashSlpMainNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )
    # Configuration for Bitcoin Cash Simple Ledger Protocol test net
    BitcoinCashSlpTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashSlpTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinCashSlpTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashSlpTestNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashSlpTestNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashSlpTestNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )

    # Configuration for BitcoinSV main net
    BitcoinSvMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinSvMainNet.CoinNames(),
        coin_idx=236,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinSvMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.BitcoinSvMainNet.Params("p2sh_net_ver"),
        },
    )
    # Configuration for BitcoinSV test net
    BitcoinSvTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinSvTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinSvTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.BitcoinSvTestNet.Params("p2sh_net_ver"),
        },
    )

    # Configuration for Dash main net
    DashMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DashMainNet.CoinNames(),
        coin_idx=5,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.DashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.DashMainNet.Params("p2sh_net_ver"),
        },
    )
    # Configuration for Dash test net
    DashTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.DashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.DashTestNet.Params("p2sh_net_ver"),
        },
    )

    # Configuration for Dogecoin main net
    DogecoinMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DogecoinMainNet.CoinNames(),
        coin_idx=3,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=Bip32KeyNetVersions(b"\x02\xfa\xca\xfd",
                                        b"\x02\xfa\xc3\x98"),   # dgub / dgpv
        wif_net_ver=CoinsConf.DogecoinMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.DogecoinMainNet.Params("p2sh_net_ver"),
        },
    )
    # Configuration for Dogecoin test net
    DogecoinTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DogecoinTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=Bip32KeyNetVersions(b"\x04\x32\xa9\xa8",
                                        b"\x04\x32\xa2\x43"),   # tgub / tgpv
        wif_net_ver=CoinsConf.DogecoinTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.DogecoinTestNet.Params("p2sh_net_ver"),
        },
    )

    # Configuration for eCash main net
    EcashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.EcashMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.EcashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.EcashMainNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.EcashMainNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.EcashMainNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )
    # Configuration for eCash test net
    EcashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.EcashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.EcashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2SHAddrEncoder,
        addr_params={
            "std": {
                "net_ver": CoinsConf.EcashTestNet.Params("p2sh_std_net_ver"),
                "hrp": CoinsConf.EcashTestNet.Params("p2sh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.EcashTestNet.Params("p2sh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2SHAddrEncoder,
    )

    # Configuration for Litecoin main net
    LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
        coin_names=CoinsConf.LitecoinMainNet.CoinNames(),
        coin_idx=2,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        alt_key_net_ver=Bip32KeyNetVersions(b"\x01\xb2\x6e\xf6",
                                            b"\x01\xb2\x67\x92"),   # Mtpv / Mtub
        wif_net_ver=CoinsConf.LitecoinMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "std_net_ver": CoinsConf.LitecoinMainNet.Params("p2sh_std_net_ver"),
            "depr_net_ver": CoinsConf.LitecoinMainNet.Params("p2sh_depr_net_ver"),
        },
    )
    # Configuration for Litecoin test net
    LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
        coin_names=CoinsConf.LitecoinTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                        b"\x04\x36\xef\x7d"),       # ttub / ttpv
        alt_key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                            b"\x04\x36\xef\x7d"),   # ttub / ttpv
        wif_net_ver=CoinsConf.LitecoinTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "std_net_ver": CoinsConf.LitecoinTestNet.Params("p2sh_std_net_ver"),
            "depr_net_ver": CoinsConf.LitecoinTestNet.Params("p2sh_depr_net_ver"),
        },
    )

    # Configuration for Zcash main net
    ZcashMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.ZcashMainNet.CoinNames(),
        coin_idx=133,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.ZcashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.ZcashMainNet.Params("p2sh_net_ver"),
        },
    )
    # Configuration for Zcash test net
    ZcashTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.ZcashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP49_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.ZcashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2SHAddrEncoder,
        addr_params={
            "net_ver": CoinsConf.ZcashTestNet.Params("p2sh_net_ver"),
        },
    )
