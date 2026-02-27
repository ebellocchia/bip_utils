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
Module for TON mnemonic generation.
Reference: https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts
"""

# Imports
import secrets
from typing import Union

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter
from bip_utils.ton.mnemonic.ton_mnemonic import TonLanguages, TonMnemonic, TonMnemonicConst, TonWordsNum
from bip_utils.ton.mnemonic.ton_seed_utils import TonSeedUtils
from bip_utils.utils.mnemonic import Mnemonic


class TonMnemonicGeneratorConst:
    """Class container for TON mnemonic generator constants."""

    # Max attempts to generate a valid mnemonic
    MAX_ATTEMPTS: int = 10**6


class TonMnemonicGenerator:
    """
    TON mnemonic generator class.
    It generates 12 or 24-words mnemonic in according to TON wallets.
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

    def FromWordsNumber(self,
                        words_num: Union[int, TonWordsNum] = TonWordsNum.WORDS_NUM_24,
                        passphrase: str = "") -> Mnemonic:
        """
        Generate mnemonic with the specified words.

        Args:
            words_num (int or TonWordsNum, optional): Number of words (12 or 24 by default)
            passphrase (str, optional)              : Passphrase (empty by default)

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid or if unable to generate a valid mnemonic
        """
        # Check words number
        if words_num not in TonMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        words_list = Bip39WordsListGetter().GetByLanguage(self.m_lang.value)
        for _ in range(TonMnemonicGeneratorConst.MAX_ATTEMPTS):
            # Generate mnemonic
            mnemonic_array = []
            for _ in range(words_num):
                idx = secrets.randbelow(TonMnemonicConst.WORDS_LIST_NUM)
                mnemonic_array.append(words_list.GetWordAtIdx(idx))
            mnemonic = " ".join(mnemonic_array)

            # Stop if generated mnemonic is valid
            if passphrase != "":
                if TonSeedUtils.IsPasswordNeeded(mnemonic):
                    return TonMnemonic(mnemonic_array)
            elif TonSeedUtils.IsBasicSeed(TonSeedUtils.GetEntropyBytes(mnemonic, passphrase)):
                return TonMnemonic(mnemonic_array)

        raise ValueError("Unable to generate a valid mnemonic")
