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
from enum import Enum, auto, unique


@unique
class AddrTypes(Enum):
    """ Enumerative for address types. """

    ALGO = auto(),
    AVAX_P = auto(),
    AVAX_X = auto(),
    ATOM = auto(),
    EGLD = auto(),
    ETH = auto(),
    FIL = auto(),
    NANO = auto(),
    NEO = auto(),
    OKEX = auto(),
    ONE = auto(),
    P2PKH = auto(),
    P2PKH_BCH = auto(),
    P2SH = auto(),
    P2SH_BCH = auto(),
    P2WPKH = auto(),
    SOL = auto(),
    SUBSTRATE = auto(),
    TRX = auto(),
    XLM = auto()
    XMR = auto(),
    XRP = auto(),
    XTZ = auto(),
    ZIL = auto(),
