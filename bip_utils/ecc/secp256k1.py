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
from bip_utils.ecc.conf import EccConf
from bip_utils.ecc.elliptic_curve import EllipticCurve
from bip_utils.ecc.ikeys import IPoint


_CURVE_ORDER: int
_GENERATOR: IPoint

# Select the correct curve order and generator
if EccConf.USE_COINCURVE:
    from bip_utils.ecc.secp256k1_keys_coincurve import Secp256k1Point, Secp256k1PublicKey, Secp256k1PrivateKey

    _CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _GENERATOR = Secp256k1Point.FromCoordinates(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                                                        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
else:
    from ecdsa.ecdsa import generator_secp256k1
    from bip_utils.ecc.secp256k1_keys_ecdsa import Secp256k1Point, Secp256k1PublicKey, Secp256k1PrivateKey

    _CURVE_ORDER = generator_secp256k1.order()
    _GENERATOR = Secp256k1Point(generator_secp256k1)


class Secp256k1Const:
    """ Class container for Secp256k1 constants. """

    # Curve name
    NAME: str = "Secp256k1"
    # Curve order
    CURVE_ORDER: int = _CURVE_ORDER
    # Curve generator point
    GENERATOR: IPoint = _GENERATOR


# Secp256k1 curve definition
Secp256k1: EllipticCurve = EllipticCurve(Secp256k1Const.NAME,
                                         Secp256k1Const.CURVE_ORDER,
                                         Secp256k1Const.GENERATOR,
                                         Secp256k1Point,
                                         Secp256k1PublicKey,
                                         Secp256k1PrivateKey)
