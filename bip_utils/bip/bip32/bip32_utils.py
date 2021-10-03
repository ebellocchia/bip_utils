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
from bip_utils.utils import BitUtils


class Bip32UtilsConst:
    """ Class container for BIP32 utility constants. """

    # Hardened bit index
    HARDENED_BIT_IDX: int = 30


class Bip32Utils:
    """ BIP32 utility class. It contains some helper method for Bip32 class. """

    @staticmethod
    def HardenIndex(index: int) -> int:
        """ Harden the specified index and return it.

        Args:
            index (int): Index

        Returns:
            int: Hardened index
        """
        return BitUtils.SetBit(index, Bip32UtilsConst.HARDENED_BIT_IDX)

    @staticmethod
    def UnhardenIndex(index: int) -> int:
        """ Unharden the specified index and return it.

        Args:
            index (int): Index

        Returns:
            int: Unhardened index
        """
        return BitUtils.ResetBit(index, Bip32UtilsConst.HARDENED_BIT_IDX)

    @staticmethod
    def IsHardenedIndex(index: int) -> bool:
        """ Get if the specified index is hardened.

        Args:
            index (int): Index

        Returns:
            bool: True if hardened, false otherwise
        """
        return BitUtils.IsBitSet(index, Bip32UtilsConst.HARDENED_BIT_IDX)
