# Copyright (c) 2023 Emanuele Bellocchia
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

"""Module for getting brainwallet algorithms."""

# Imports
from typing import Dict, Type

from bip_utils.brainwallet.brainwallet_algo import (
    BrainwalletAlgoDoubleSha256, BrainwalletAlgoPbkdf2HmacSha512, BrainwalletAlgos, BrainwalletAlgoScrypt,
    BrainwalletAlgoSha256
)
from bip_utils.brainwallet.ibrainwallet_algo import IBrainwalletAlgo


class BrainwalletAlgoGetterConst:
    """Class container for brainwallet algorithm getter constants."""

    # Map from BrainwalletAlgos to algorithm classes
    ENUM_TO_ALGO: Dict[BrainwalletAlgos, Type[IBrainwalletAlgo]] = {
        BrainwalletAlgos.SHA256: BrainwalletAlgoSha256,
        BrainwalletAlgos.DOUBLE_SHA256: BrainwalletAlgoDoubleSha256,
        BrainwalletAlgos.PBKDF2_HMAC_SHA512: BrainwalletAlgoPbkdf2HmacSha512,
        BrainwalletAlgos.SCRYPT: BrainwalletAlgoScrypt,
    }


class BrainwalletAlgoGetter:
    """
    Brainwallet algorithm getter class.
    It allows to get the a specific brainwallet algorithm.
    """

    @staticmethod
    def GetAlgo(algo_type: BrainwalletAlgos) -> Type[IBrainwalletAlgo]:
        """
        Get algorithm class.

        Args:
            algo_type (BrainwalletAlgos): Algorithm type

        Returns:
            IBrainwalletAlgo class: Algorithm class

        Raises:
            TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
        """
        if not isinstance(algo_type, BrainwalletAlgos):
            raise TypeError("Algorithm type is not an enumerative of BrainwalletAlgos")
        return BrainwalletAlgoGetterConst.ENUM_TO_ALGO[algo_type]
