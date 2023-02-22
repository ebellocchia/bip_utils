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

"""Module for CIP-1852 coins configuration."""

# Imports
from bip_utils.addr import AdaShelleyAddrEncoder, AdaShelleyAddrNetworkTags
from bip_utils.bip.bip32 import Bip32Const, Bip32KholawEd25519
from bip_utils.bip.conf.common import DER_PATH_NON_HARDENED_FULL, BipCoinConf
from bip_utils.cardano.bip32.cardano_icarus_bip32 import CardanoIcarusBip32
from bip_utils.coin_conf import CoinsConf
from bip_utils.slip.slip44 import Slip44


class Cip1852Conf:
    """Class container for CIP-1852 configuration."""

    # Configuration for Cardano main net (Icarus)
    CardanoIcarusMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.CardanoMainNet.CoinNames(),
        coin_idx=Slip44.CARDANO,
        is_testnet=False,
        def_path=DER_PATH_NON_HARDENED_FULL,
        key_net_ver=Bip32Const.KHOLAW_KEY_NET_VERSIONS,
        wif_net_ver=None,
        bip32_cls=CardanoIcarusBip32,
        addr_cls=AdaShelleyAddrEncoder,
        addr_params={
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
    )

    # Configuration for Cardano test net (Icarus)
    CardanoIcarusTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.CardanoTestNet.CoinNames(),
        coin_idx=Slip44.CARDANO,
        is_testnet=True,
        def_path=DER_PATH_NON_HARDENED_FULL,
        key_net_ver=Bip32Const.TEST_NET_KEY_NET_VERSIONS,
        wif_net_ver=None,
        bip32_cls=CardanoIcarusBip32,
        addr_cls=AdaShelleyAddrEncoder,
        addr_params={
            "net_tag": AdaShelleyAddrNetworkTags.TESTNET,
        },
    )

    # Configuration for Cardano main net (Ledger)
    CardanoLedgerMainNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.CardanoMainNet.CoinNames(),
        coin_idx=Slip44.CARDANO,
        is_testnet=False,
        def_path=DER_PATH_NON_HARDENED_FULL,
        key_net_ver=Bip32Const.KHOLAW_KEY_NET_VERSIONS,
        wif_net_ver=None,
        bip32_cls=Bip32KholawEd25519,
        addr_cls=AdaShelleyAddrEncoder,
        addr_params={
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
    )

    # Configuration for Cardano test net (Ledger)
    CardanoLedgerTestNet: BipCoinConf = BipCoinConf(
        coin_names=CoinsConf.CardanoTestNet.CoinNames(),
        coin_idx=Slip44.CARDANO,
        is_testnet=True,
        def_path=DER_PATH_NON_HARDENED_FULL,
        key_net_ver=Bip32Const.TEST_NET_KEY_NET_VERSIONS,
        wif_net_ver=None,
        bip32_cls=Bip32KholawEd25519,
        addr_cls=AdaShelleyAddrEncoder,
        addr_params={
            "net_tag": AdaShelleyAddrNetworkTags.TESTNET,
        },
    )
