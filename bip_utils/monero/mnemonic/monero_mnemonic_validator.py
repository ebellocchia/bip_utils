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

"""Module for Monero mnemonic validation."""

# Imports
from typing import Optional, Union
from bip_utils.monero.mnemonic.monero_mnemonic_ex import MoneroMnemonicChecksumError
from bip_utils.monero.mnemonic.monero_mnemonic import MoneroLanguages, MoneroMnemonicDecoder
from bip_utils.utils.mnemonic import Mnemonic


class MoneroMnemonicValidator:
    """
    Monero mnemonic validator class.
    It validates a mnemonic phrase.
    """

    m_mnemonic_decoder: MoneroMnemonicDecoder

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[MoneroLanguages] = None) -> None:
        """
        Construct the class from mnemonic.

        Args:
            lang (MoneroLanguages, optional): Language, None for automatic detection
        """
        self.m_mnemonic_decoder = MoneroMnemonicDecoder(lang)

    def Validate(self,
                 mnemonic: Union[str, Mnemonic]) -> None:
        """
        Validate the mnemonic specified at construction.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Raises:
            MoneroMnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """

        # Just get entropy bytes without returning it, since it will validate the mnemonic
        self.m_mnemonic_decoder.Decode(mnemonic)

    def IsValid(self,
                mnemonic: Union[str, Mnemonic]) -> bool:
        """
        Get if the mnemonic specified at construction is valid.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bool: True if valid, False otherwise
        """

        # Simply try to validate
        try:
            self.Validate(mnemonic)
            return True
        except (ValueError, MoneroMnemonicChecksumError):
            return False
