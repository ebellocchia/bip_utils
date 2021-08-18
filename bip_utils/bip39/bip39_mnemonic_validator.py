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

# BIP-0039 reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

# Imports
from typing import Optional, Union
from bip_utils.bip39.bip39_ex import Bip39ChecksumError
from bip_utils.bip39.bip39_mnemonic import Bip39Languages, Bip39Mnemonic, Bip39MnemonicEncoder


class Bip39MnemonicValidator:
    """ BIP39 mnemonic validator class. It validates a mnemonic phrase. """

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[Bip39Languages] = None) -> None:
        """ Construct the class from mnemonic.

        Args:
            lang (Bip39Languages, optional): Language, None for automatic detection
        """
        self.m_mnemonic_encoder = Bip39MnemonicEncoder(lang)

    def Validate(self,
                 mnemonic: Union[str, Bip39Mnemonic]) -> None:
        """ Validate the mnemonic specified at construction.

        Args:
            mnemonic (str or Bip39Mnemonic object): Mnemonic

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """

        # Just get entropy bytes without returning it, since it will validate the mnemonic
        self.m_mnemonic_encoder.Encode(mnemonic)

    def IsValid(self,
                mnemonic: Union[str, Bip39Mnemonic]) -> bool:
        """ Get if the mnemonic specified at construction is valid.

        Args:
            mnemonic (str or Bip39Mnemonic object): Mnemonic

        Returns:
            bool: True if valid, False otherwise
        """

        # Simply try to validate
        try:
            self.Validate(mnemonic)
            return True
        except (ValueError, Bip39ChecksumError):
            return False
