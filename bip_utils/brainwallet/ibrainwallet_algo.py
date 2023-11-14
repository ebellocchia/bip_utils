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

"""Module for implementing algorithms for brainwallet generation."""

# Imports
from abc import ABC, abstractmethod
from typing import Any


class IBrainwalletAlgo(ABC):
    """
    Interface for an algorithm that computes a private key for a brainwallet.
    It can be inherited to implement custom algorithms.
    """

    @staticmethod
    @abstractmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        """
        Compute the private key from the specified passphrase.

        Args:
            passphrase (str): Passphrase
            **kwargs        : Arbitrary arguments depending on the algorithm

        Returns:
            bytes: Private key bytes
        """
