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

"""Module for Monero coins configuration."""

# Imports
from bip_utils.coin_conf import MoneroConf
from bip_utils.monero.conf.monero_coin_conf import MoneroCoinConf


# Configuration for Monero main net
MoneroMainNet: MoneroCoinConf = MoneroCoinConf(
    coin_name=MoneroConf.COIN_NAME_MN,
    addr_net_ver=MoneroConf.ADDR_NET_VER_MN,
    int_addr_net_ver=MoneroConf.ADDR_INT_NET_VER_MN,
    subaddr_net_ver=MoneroConf.SUBADDR_NET_VER_MN,
)


# Configuration for Monero stage net
MoneroStageNet: MoneroCoinConf = MoneroCoinConf(
    coin_name=MoneroConf.COIN_NAME_SN,
    addr_net_ver=MoneroConf.ADDR_NET_VER_SN,
    int_addr_net_ver=MoneroConf.ADDR_INT_NET_VER_SN,
    subaddr_net_ver=MoneroConf.SUBADDR_NET_VER_SN,
)


# Configuration for Monero test net
MoneroTestNet: MoneroCoinConf = MoneroCoinConf(
    coin_name=MoneroConf.COIN_NAME_TN,
    addr_net_ver=MoneroConf.ADDR_NET_VER_TN,
    int_addr_net_ver=MoneroConf.ADDR_INT_NET_VER_TN,
    subaddr_net_ver=MoneroConf.SUBADDR_NET_VER_TN,
)
