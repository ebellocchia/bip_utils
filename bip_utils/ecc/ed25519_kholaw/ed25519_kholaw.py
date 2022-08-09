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

"""Module with ed25519-kholaw curve."""

# Imports
from bip_utils.ecc.curve.elliptic_curve import EllipticCurve
from bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_const import Ed25519KholawConst
from bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_keys import Ed25519KholawPrivateKey, Ed25519KholawPublicKey
from bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_point import Ed25519KholawPoint


# Ed25519-Kholaw curve definition
Ed25519Kholaw: EllipticCurve = EllipticCurve(Ed25519KholawConst.NAME,
                                             Ed25519KholawConst.CURVE_ORDER,
                                             Ed25519KholawConst.GENERATOR,
                                             Ed25519KholawPoint,
                                             Ed25519KholawPublicKey,
                                             Ed25519KholawPrivateKey)
