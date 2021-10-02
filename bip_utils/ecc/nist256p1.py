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
from ecdsa.ecdsa import generator_256
from bip_utils.ecc.elliptic_curve import EllipticCurve
from bip_utils.ecc.ikeys import IPoint
from bip_utils.ecc.nist256p1_keys import Nist256p1Point, Nist256p1PublicKey, Nist256p1PrivateKey


class Nist256p1Const:
    """ Class container for Nist256p1 constants. """

    # Curve name
    NAME: str = "Nist256p1"
    # Curve order
    CURVE_ORDER: int = generator_256.order()
    # Curve generator point
    GENERATOR: IPoint = Nist256p1Point(generator_256)


# Nist256p1 curve definition
Nist256p1: EllipticCurve = EllipticCurve(Nist256p1Const.NAME,
                                         Nist256p1Const.CURVE_ORDER,
                                         Nist256p1Const.GENERATOR,
                                         Nist256p1Point,
                                         Nist256p1PublicKey,
                                         Nist256p1PrivateKey)
