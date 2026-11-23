# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module for SLIP39 mnemonic validation."""

# Imports
from typing import Union

from bip_utils.slip.slip39.slip39_mnemonic_decoder import Slip39MnemonicDecoder
from bip_utils.utils.mnemonic import Mnemonic, MnemonicChecksumError


class Slip39MnemonicValidator:
    """
    SLIP39 mnemonic validator class.
    It validates a single share mnemonic (words, length, padding and checksum).
    """

    m_decoder: Slip39MnemonicDecoder

    def __init__(self) -> None:
        """Construct class."""
        self.m_decoder = Slip39MnemonicDecoder()

    def Validate(self,
                 mnemonic: Union[str, Mnemonic]) -> None:
        """
        Validate the specified mnemonic.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        self.m_decoder.Decode(mnemonic)

    def IsValid(self,
                mnemonic: Union[str, Mnemonic]) -> bool:
        """
        Get if the specified mnemonic is valid.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            self.Validate(mnemonic)
            return True
        except (ValueError, MnemonicChecksumError):
            return False
