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

"""Module for BIP44 coins configuration."""

# Imports
from bip_utils.addr import (
    AlgoAddr, AtomAddr, AvaxPChainAddr, AvaxXChainAddr, EgldAddr,
    EosAddr, EthAddr, FilSecp256k1Addr, OkexAddr, NanoAddr, NearAddr,
    NeoAddr, OneAddr, P2PKHAddr, BchP2PKHAddr, SolAddr,
    SubstrateEd25519Addr, TrxAddr, XlmAddrTypes, XlmAddr, XmrAddr,
    XrpAddr, XtzAddrPrefixes, XtzAddr, ZilAddr
)
from bip_utils.bip.bip32 import (
    Bip32Const, Bip32KeyNetVersions, Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip, Bip32Nist256p1, Bip32Secp256k1
)
from bip_utils.bip.conf.common import (
    BipCoinConf, BipBitcoinCashConf, BipLitecoinConf, HARDENED_DEF_PATH, NOT_HARDENED_DEF_PATH
)
from bip_utils.coin_conf import CoinsConf


# Bitcoin key net version for main net (same as BIP32)
_BIP44_BTC_KEY_NET_VER_MAIN: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS
# Bitcoin key net version for test net (same as BIP32)
_BIP44_BTC_KEY_NET_VER_TEST: Bip32KeyNetVersions = Bip32Const.TEST_NET_KEY_NET_VERSIONS


class Bip44Conf:
    """Class container for Bip44 configuration."""

    # Configuration for Algorand
    Algorand: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Algorand.CoinNames(),
        coin_idx=283,
        is_testnet=False,
        def_path=HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=AlgoAddr,
        addr_params={},
    )

    # Configuration for Avax C-Chain
    AvaxCChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.AvaxCChain.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )
    # Configuration for Avax P-Chain
    AvaxPChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.AvaxPChain.CoinNames(),
        coin_idx=9000,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AvaxPChainAddr,
        addr_params={},
    )
    # Configuration for Avax X-Chain
    AvaxXChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.AvaxXChain.CoinNames(),
        coin_idx=9000,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AvaxXChainAddr,
        addr_params={},
    )

    # Configuration for Band Protocol
    BandProtocol: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BandProtocol.CoinNames(),
        coin_idx=494,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.BandProtocol.Params("addr_hrp"),
        },
    )

    # Configuration for Binance Chain
    BinanceChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BinanceChain.CoinNames(),
        coin_idx=714,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.BinanceChain.Params("addr_hrp"),
        },
    )
    # Configuration for Binance Smart Chain
    BinanceSmartChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BinanceSmartChain.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Bitcoin main net
    BitcoinMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinMainNet.CoinNames(),
        coin_idx=0,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver"),
        },
    )
    # Configuration for Bitcoin test net
    BitcoinTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.BitcoinTestNet.Params("p2pkh_net_ver"),
        },
    )

    # Configuration for Bitcoin Cash main net
    BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinCashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )
    # Configuration for Bitcoin Cash test net
    BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinCashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashTestNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashTestNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashTestNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )

    # Configuration for Bitcoin Cash Simple Ledger Protocol main net
    BitcoinCashSlpMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashSlpMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinCashSlpMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashSlpMainNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashSlpMainNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashSlpMainNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )
    # Configuration for Bitcoin Cash Simple Ledger Protocol test net
    BitcoinCashSlpTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.BitcoinCashSlpTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinCashSlpTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.BitcoinCashSlpTestNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.BitcoinCashSlpTestNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.BitcoinCashSlpTestNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )

    # Configuration for BitcoinSV main net
    BitcoinSvMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinSvMainNet.CoinNames(),
        coin_idx=236,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.BitcoinSvMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.BitcoinSvMainNet.Params("p2pkh_net_ver"),
        },
    )
    # Configuration for BitcoinSV test net
    BitcoinSvTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.BitcoinSvTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.BitcoinSvTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.BitcoinSvTestNet.Params("p2pkh_net_ver"),
        },
    )

    # Configuration for Celo
    Celo: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Celo.CoinNames(),
        coin_idx=52752,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Cosmos
    Cosmos: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Cosmos.CoinNames(),
        coin_idx=118,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.Cosmos.Params("addr_hrp"),
        },
    )

    # Configuration for Dash main net
    DashMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DashMainNet.CoinNames(),
        coin_idx=5,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.DashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.DashMainNet.Params("p2pkh_net_ver"),
        },
    )
    # Configuration for Dash test net
    DashTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.DashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.DashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.DashTestNet.Params("p2pkh_net_ver"),
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
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.DogecoinMainNet.Params("p2pkh_net_ver"),
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
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.DogecoinTestNet.Params("p2pkh_net_ver"),
        },
    )

    # Configuration for eCash main net
    EcashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.EcashMainNet.CoinNames(),
        coin_idx=145,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.EcashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.EcashMainNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.EcashMainNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.EcashMainNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )
    # Configuration for eCash test net
    EcashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
        coin_names=CoinsConf.EcashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.EcashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=BchP2PKHAddr,
        addr_params={
            "std": {
                "net_ver": CoinsConf.EcashTestNet.Params("p2pkh_std_net_ver"),
                "hrp": CoinsConf.EcashTestNet.Params("p2pkh_std_hrp"),
            },
            "legacy": {
                "net_ver": CoinsConf.EcashTestNet.Params("p2pkh_legacy_net_ver"),
            }
        },
        addr_cls_legacy=P2PKHAddr,
    )

    # Configuration for Elrond
    Elrond: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Elrond.CoinNames(),
        coin_idx=508,
        is_testnet=False,
        def_path=HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=EgldAddr,
        addr_params={},
    )

    # Configuration for Eos
    Eos: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Eos.CoinNames(),
        coin_idx=194,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EosAddr,
        addr_params={},
    )

    # Configuration for Ethereum
    Ethereum: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Ethereum.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )
    # Configuration for Ethereum Classic
    EthereumClassic: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.EthereumClassic.CoinNames(),
        coin_idx=61,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Fantom Opera
    FantomOpera: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.FantomOpera.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Filecoin
    Filecoin: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Filecoin.CoinNames(),
        coin_idx=461,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=FilSecp256k1Addr,
        addr_params={},
    )

    # Configuration for Harmony One (Metamask address)
    HarmonyOneMetamask: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.HarmonyOne.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )
    # Configuration for Harmony One (Ethereum address)
    HarmonyOneEth: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.HarmonyOne.CoinNames(),
        coin_idx=1023,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )
    # Configuration for Harmony One (Atom address)
    HarmonyOneAtom: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.HarmonyOne.CoinNames(),
        coin_idx=1023,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=OneAddr,
        addr_params={},
    )

    # Configuration for Huobi Chain
    HuobiChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.HuobiChain.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for IRISnet
    IrisNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.IrisNet.CoinNames(),
        coin_idx=118,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.IrisNet.Params("addr_hrp"),
        },
    )

    # Configuration for Kava
    Kava: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Kava.CoinNames(),
        coin_idx=494,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.Kava.Params("addr_hrp"),
        },
    )

    # Configuration for Kusama (ed25519 SLIP-0010)
    KusamaEd25519Slip: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Kusama.CoinNames(),
        coin_idx=354,
        is_testnet=False,
        def_path=HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=SubstrateEd25519Addr,
        addr_params={
            "ss58_format": CoinsConf.Kusama.Params("addr_ss58_format"),
        },
    )

    # Configuration for Litecoin main net
    LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
        coin_names=CoinsConf.LitecoinMainNet.CoinNames(),
        coin_idx=2,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        alt_key_net_ver=Bip32KeyNetVersions(b"\x01\x9d\xa4\x62",
                                            b"\x01\x9d\x9c\xfe"),   # Ltpv / Ltub
        wif_net_ver=CoinsConf.LitecoinMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "std_net_ver": CoinsConf.LitecoinMainNet.Params("p2pkh_std_net_ver"),
            "depr_net_ver": CoinsConf.LitecoinMainNet.Params("p2pkh_depr_net_ver"),
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
        addr_cls=P2PKHAddr,
        addr_params={
            "std_net_ver": CoinsConf.LitecoinTestNet.Params("p2pkh_std_net_ver"),
            "depr_net_ver": CoinsConf.LitecoinTestNet.Params("p2pkh_depr_net_ver"),
        },
    )

    # Configuration for Monero (ed25519 SLIP-0010)
    MoneroEd25519Slip: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.MoneroMainNet.CoinNames(),
        coin_idx=128,
        is_testnet=False,
        def_path=HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=XmrAddr,
        addr_params={},
    )

    # Configuration for Monero (secp256k1)
    MoneroSecp256k1: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.MoneroMainNet.CoinNames(),
        coin_idx=128,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=XmrAddr,
        addr_params={},
    )

    # Configuration for Nano
    Nano: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Nano.CoinNames(),
        coin_idx=165,
        is_testnet=False,
        def_path="0'",
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Blake2bSlip,
        addr_cls=NanoAddr,
        addr_params={},
    )

    # Configuration for Near Protocol
    NearProtocol: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.NearProtocol.CoinNames(),
        coin_idx=397,
        is_testnet=False,
        def_path="0'",
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=NearAddr,
        addr_params={},
    )

    # Configuration for Neo
    Neo: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Neo.CoinNames(),
        coin_idx=888,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Nist256p1,
        addr_cls=NeoAddr,
        addr_params={
            "ver": CoinsConf.Neo.Params("addr_ver"),
        },
    )

    # Configuration for NG
    NineChroniclesGold: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.NineChroniclesGold.CoinNames(),
        coin_idx=567,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for OKEx Chain (Ethereum address)
    OkexChainEth: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.OkexChain.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for OKEx Chain (Atom address)
    OkexChainAtom: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.OkexChain.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=OkexAddr,
        addr_params={},
    )

    # Configuration for OKEx Chain (old Atom address)
    OkexChainAtomOld: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.OkexChain.CoinNames(),
        coin_idx=996,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=OkexAddr,
        addr_params={},
    )

    # Configuration for Ontology
    Ontology: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Ontology.CoinNames(),
        coin_idx=1024,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Nist256p1,
        addr_cls=NeoAddr,
        addr_params={
            "ver": CoinsConf.Ontology.Params("addr_ver"),
        },
    )

    # Configuration for Osmosis
    Osmosis: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Osmosis.CoinNames(),
        coin_idx=118,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.Osmosis.Params("addr_hrp"),
        },
    )

    # Configuration for Polkadot (ed25519 SLIP-0010)
    PolkadotEd25519Slip: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Polkadot.CoinNames(),
        coin_idx=354,
        is_testnet=False,
        def_path=HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=SubstrateEd25519Addr,
        addr_params={
            "ss58_format": CoinsConf.Polkadot.Params("addr_ss58_format"),
        },
    )

    # Configuration for Polygon
    Polygon: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Polygon.CoinNames(),
        coin_idx=60,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Ripple
    Ripple: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Ripple.CoinNames(),
        coin_idx=144,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=XrpAddr,
        addr_params={},
    )

    # Configuration for Secret Network (old path)
    SecretNetworkOld: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.SecretNetwork.CoinNames(),
        coin_idx=118,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.SecretNetwork.Params("addr_hrp"),
        },
    )
    # Configuration for Secret Network (new path)
    SecretNetworkNew: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.SecretNetwork.CoinNames(),
        coin_idx=529,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.SecretNetwork.Params("addr_hrp"),
        },
    )

    # Configuration for Solana
    Solana: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Solana.CoinNames(),
        coin_idx=501,
        is_testnet=False,
        def_path="0'",
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=SolAddr,
        addr_params={},
    )

    # Configuration for Stellar
    Stellar: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Stellar.CoinNames(),
        coin_idx=148,
        is_testnet=False,
        def_path="0'",
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=XlmAddr,
        addr_params={"addr_type": XlmAddrTypes.PUB_KEY},
    )

    # Configuration for Terra
    Terra: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Terra.CoinNames(),
        coin_idx=330,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=AtomAddr,
        addr_params={
            "hrp": CoinsConf.Terra.Params("addr_hrp"),
        },
    )

    # Configuration for Tezos
    Tezos: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Tezos.CoinNames(),
        coin_idx=1729,
        is_testnet=False,
        def_path="0'/0'",
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Ed25519Slip,
        addr_cls=XtzAddr,
        addr_params={"prefix": XtzAddrPrefixes.TZ1},
    )

    # Configuration for Theta
    Theta: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Theta.CoinNames(),
        coin_idx=500,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Tron
    Tron: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Tron.CoinNames(),
        coin_idx=195,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=TrxAddr,
        addr_params={},
    )

    # Configuration for VeChain
    VeChain: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.VeChain.CoinNames(),
        coin_idx=818,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=EthAddr,
        addr_params={},
    )

    # Configuration for Verge
    Verge: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Verge.CoinNames(),
        coin_idx=77,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.Verge.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.Verge.Params("p2pkh_net_ver"),
        },
    )

    # Configuration for Zcash main net
    ZcashMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.ZcashMainNet.CoinNames(),
        coin_idx=133,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=CoinsConf.ZcashMainNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.ZcashMainNet.Params("p2pkh_net_ver"),
        },
    )
    # Configuration for Zcash test net
    ZcashTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.ZcashTestNet.CoinNames(),
        coin_idx=1,
        is_testnet=True,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
        wif_net_ver=CoinsConf.ZcashTestNet.Params("wif_net_ver"),
        bip32_cls=Bip32Secp256k1,
        addr_cls=P2PKHAddr,
        addr_params={
            "net_ver": CoinsConf.ZcashTestNet.Params("p2pkh_net_ver"),
        },
    )

    # Configuration for Zilliqa
    Zilliqa: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.Zilliqa.CoinNames(),
        coin_idx=313,
        is_testnet=False,
        def_path=NOT_HARDENED_DEF_PATH,
        key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
        wif_net_ver=None,
        bip32_cls=Bip32Secp256k1,
        addr_cls=ZilAddr,
        addr_params={},
    )
