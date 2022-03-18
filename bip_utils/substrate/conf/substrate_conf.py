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

"""
Module for Substrate coins configuration.
Reference: https://wiki.polkadot.network/docs/build-ss58-registry
"""

# Imports
from bip_utils.coin_conf import CoinsConf
from bip_utils.substrate.conf.substrate_coin_conf import SubstrateCoinConf


class SubstrateConf:
    """Class container for Substrate configuration."""

    # Configuration for Acala
    Acala: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Acala)

    # Configuration for Bifrost
    Bifrost: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Bifrost)

    # Configuration for ChainX
    ChainX: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.ChainX)

    # Configuration for Edgeware
    Edgeware: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Edgeware)

    # Configuration for generic Substrate coin
    Generic: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.GenericSubstrate)

    # Configuration for Karura
    Karura: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Karura)

    # Configuration for Kusama
    Kusama: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Kusama)

    # Configuration for Moonbeam
    Moonbeam: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Moonbeam)

    # Configuration for Moonriver
    Moonriver: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Moonriver)

    # Configuration for Phala
    Phala: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Phala)

    # Configuration for Plasm
    Plasm: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Plasm)

    # Configuration for Polkadot
    Polkadot: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Polkadot)

    # Configuration for Sora
    Sora: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Sora)

    # Configuration for Stafi
    Stafi: SubstrateCoinConf = SubstrateCoinConf.FromCoinConf(CoinsConf.Stafi)
