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

"""Module for Algorand mnemonic generation."""

# Imports
from typing import Dict, Optional, Union

from bip_utils.bip.bip39.bip39_mnemonic import Bip39Languages

from bip_utils.ton.mnemonic.ton_mnemonic import TonWordsNum
from bip_utils.utils.mnemonic import Mnemonic
import secrets
from bip_utils.bip.bip39.bip39_mnemonic import Bip39MnemonicConst
from bip_utils.ton.mnemonic.ton_mnemonic_validator import TonMnemonicValidator
from bip_utils.ton.mnemonic.ton_mnemonic import TonMnemonicConst
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter


class TonMnemonicGenerator:
    """
    TON mnemonic generator class.
    It generates 12 or 24-words mnemonic in according to TON wallets.
    """


    def __init__(self) -> None:
        """
        Construct class.
        """
        

    def FromWordsNumber(self,
                        words_num: Optional[Union[int, TonWordsNum]] = 24, passphrase: Optional[str] = "") -> Mnemonic:
        """
        Generate mnemonic with the specified words.
        See https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts

        Args:
            words_num (int or TonWordsNum): Number of words (12 or 24)
            passphrase (str, optional): Passphrase. Default is empty string.

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid
        """
        ton_mnemonic_validator = TonMnemonicValidator()
        while True:

            # Check words number
            if words_num not in TonMnemonicConst. MNEMONIC_WORD_NUM:
                raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

            # Get word list
            words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)


            # Generate mnemonic
        
            mnemonic_array = []

            for i in range(words_num):
                idx = secrets.randbelow(Bip39MnemonicConst.WORDS_LIST_NUM)
                mnemonic_array.append(words_list.GetWordAtIdx(idx))
            
            mnemonic = " ".join(mnemonic_array)
        
            # If derived mnemonic is not valid continue loop and generate another one, otherwise break loop and return it
            if not ton_mnemonic_validator.IsValid(mnemonic, passphrase):
                continue  
            break

        return mnemonic

