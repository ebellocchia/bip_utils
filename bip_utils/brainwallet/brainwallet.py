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

"""Module for keys generation using a brainwallet (i.e. passphrase chosen by the user)."""

# Imports
from __future__ import annotations

from typing import Any, Type

from bip_utils.bip.bip44 import Bip44
from bip_utils.bip.bip44_base import Bip44Base, Bip44PrivateKey, Bip44PublicKey
from bip_utils.bip.conf.bip44 import Bip44Coins
from bip_utils.brainwallet.brainwallet_algo import BrainwalletAlgos
from bip_utils.brainwallet.brainwallet_algo_getter import BrainwalletAlgoGetter
from bip_utils.brainwallet.ibrainwallet_algo import IBrainwalletAlgo


# Alias for Bip44Coins
BrainwalletCoins = Bip44Coins


class Brainwallet:
    """
    Brainwallet class.
    It allows to generate a key pair from a passphrase chosen by the user
    for different coins and with different algorithms.
    """

    bip44_obj: Bip44Base

    @classmethod
    def Generate(cls,
                 passhrase: str,
                 coin_type: BrainwalletCoins,
                 algo_type: BrainwalletAlgos,
                 **algo_params: Any) -> Brainwallet:
        """
        Generate a brainwallet from the specified passphrase and coin with the specified algorithm.

        Args:
            passhrase (str)             : Passphrase
            coin_type (BrainwalletCoins): Coin type
            algo_type (BrainwalletAlgos): Algorithm type
            **algo_params               : Algorithm parameters, if any

        Returns:
            Brainwallet object: Algorithm class

        Raises:
            TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
                       or coin type is not of a BrainwalletCoins enumerative
        """
        return cls.GenerateWithCustomAlgo(
            passhrase,
            coin_type,
            BrainwalletAlgoGetter.GetAlgo(algo_type),
            **algo_params
        )

    @classmethod
    def GenerateWithCustomAlgo(cls,
                               passhrase: str,
                               coin_type: BrainwalletCoins,
                               algo_cls: Type[IBrainwalletAlgo],
                               **algo_params: Any) -> Brainwallet:
        """
        Generate a brainwallet from the specified passphrase and coin with a custom algorithm.

        Args:
            passhrase (str)                  : Passphrase
            coin_type (BrainwalletCoins)     : Coin type
            algo_cls (IBrainwalletAlgo class): Algorithm class
            **algo_params                    : Algorithm parameters, if any

        Returns:
            Brainwallet object: Algorithm class

        Raises:
            TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
                       or coin type is not of a BrainwalletCoins enumerative
        """
        return cls(
            Bip44.FromPrivateKey(
                algo_cls.ComputePrivateKey(passhrase, **algo_params),
                coin_type
            )
        )

    def __init__(self,
                 bip44_obj: Bip44Base) -> None:
        """
        Construct class.

        Args:
            bip44_obj (Bip44Base object): Bip44Base object
        """
        self.bip44_obj = bip44_obj

    def PublicKey(self) -> Bip44PublicKey:
        """
        Return the public key.

        Returns:
            Bip44PublicKey object: Bip44PublicKey object
        """
        return self.bip44_obj.PublicKey()

    def PrivateKey(self) -> Bip44PrivateKey:
        """
        Return the private key.

        Returns:
            Bip44PrivateKey object: Bip44PrivateKey object
        """
        return self.bip44_obj.PrivateKey()
