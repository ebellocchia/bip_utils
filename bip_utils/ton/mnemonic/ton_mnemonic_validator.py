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

"""
Module for TON mnemonic validation.
Reference: https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts
"""

# Imports
from typing import Union

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter
from bip_utils.ton.mnemonic.ton_mnemonic import TonLanguages, TonMnemonic
from bip_utils.ton.mnemonic.ton_seed_utils import TonSeedUtils
from bip_utils.utils.mnemonic.mnemonic import Mnemonic


class TonMnemonicValidator:
    """
    TON mnemonic validator class.
    It validates a mnemonic phrase.
    """

    m_lang: TonLanguages

    def __init__(self,
                 lang: TonLanguages = TonLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (TonLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a TonLanguages enum
            ValueError: If language words list is not valid
        """
        if not isinstance(lang, TonLanguages):
            raise TypeError("Language is not an enumerative of TonLanguages")
        self.m_lang = lang

    def IsValid(self,
                mnemonic: Union[str, Mnemonic],
                passphrase: str = "") -> bool:
        """
        Get if the specified mnemonic is valid.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic
            passphrase (str, optional)       : Passphrase (empty by default)

        Returns:
            bool: True if valid, False otherwise
        """
        mnemonic_obj = TonMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check words
        words_list = Bip39WordsListGetter().GetByLanguage(self.m_lang.value)
        mnemonic_list = mnemonic_obj.ToList()
        for word in mnemonic_list:
            try:
                words_list.GetWordIdx(word)
            except ValueError:
                return False
        # Check seed
        if passphrase != "":
            return TonSeedUtils.IsPasswordNeeded(mnemonic_obj.ToStr())
        return TonSeedUtils.IsBasicSeed(TonSeedUtils.GetEntropyBytes(mnemonic_obj.ToStr(), passphrase))

    def Validate(self,
                mnemonic: Union[str, Mnemonic],
                passphrase: str = "") -> None:
        """
        Validate the specified mnemonic.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic
            passphrase (str, optional)       : Passphrase (empty by default)

        Raises:
            ValueError: If the mnemonic is not valid
        """
        if not self.IsValid(mnemonic, passphrase):
            raise ValueError("Invalid mnemonic")
