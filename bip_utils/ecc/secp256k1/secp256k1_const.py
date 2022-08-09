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

"""Module with secp256k1 constants."""

# Imports
from typing import Type

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.conf import EccConf


# Variables
Secp256k1Point: Type[IPoint]
Secp256k1PublicKey: Type[IPublicKey]
Secp256k1PrivateKey: Type[IPrivateKey]
_CURVE_ORDER: int
_GENERATOR: IPoint

# Use classes from coincurve version
if EccConf.USE_COINCURVE:
    from bip_utils.ecc.secp256k1.secp256k1_keys_coincurve import (
        Secp256k1PointCoincurve, Secp256k1PrivateKeyCoincurve, Secp256k1PublicKeyCoincurve
    )

    Secp256k1Point = Secp256k1PointCoincurve
    Secp256k1PublicKey = Secp256k1PublicKeyCoincurve
    Secp256k1PrivateKey = Secp256k1PrivateKeyCoincurve

    _CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _GENERATOR = Secp256k1Point.FromCoordinates(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                                                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Use classes from ecdsa version
else:
    from ecdsa.ecdsa import generator_secp256k1

    from bip_utils.ecc.secp256k1.secp256k1_keys_ecdsa import (
        Secp256k1PointEcdsa, Secp256k1PrivateKeyEcdsa, Secp256k1PublicKeyEcdsa
    )

    Secp256k1Point = Secp256k1PointEcdsa
    Secp256k1PublicKey = Secp256k1PublicKeyEcdsa
    Secp256k1PrivateKey = Secp256k1PrivateKeyEcdsa

    _CURVE_ORDER = generator_secp256k1.order()
    _GENERATOR = Secp256k1Point(generator_secp256k1)


class Secp256k1Const:
    """Class container for Secp256k1 constants."""

    # Curve name
    NAME: str = "Secp256k1"
    # Curve order
    CURVE_ORDER: int = _CURVE_ORDER
    # Curve generator point
    GENERATOR: IPoint = _GENERATOR
