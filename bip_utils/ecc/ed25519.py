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
from bip_utils.ecc.elliptic_curve import EllipticCurve
from bip_utils.ecc.ed25519_keys import Ed25519Point, Ed25519PublicKey, Ed25519PrivateKey


class Ed25519Const:
    """ Class container for Ed25519 constants. """

    # Curve name
    NAME: str = "Ed25519"
    # Curve order
    CURVE_ORDER: int = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    # Curve generator point
    GENERATOR: Ed25519Point = Ed25519Point(15112221349535400772501151409588531511454012693041857206046113283949847762202,
                                           46316835694926478169428394003475163141307993866256225615783033603165251855960,
                                           0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED)


# Ed25519 curve definition
Ed25519: EllipticCurve = EllipticCurve(Ed25519Const.NAME,
                                       Ed25519Const.CURVE_ORDER,
                                       Ed25519Const.GENERATOR,
                                       Ed25519Point,
                                       Ed25519PublicKey,
                                       Ed25519PrivateKey)
