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
import unicodedata
from typing import List, Union


class Bip39Utils:
    """ Class container for BIP39 utility functions. """

    @staticmethod
    def NormalizeNfkd(data_str: Union[str, List[str]]) -> Union[str, List[str]]:
        """ Normalize string using NFKD.

        Args:
            data_str (str or list): Input string or list of strings

        Returns:
            str or list: Normalized string or list of strings

        Raises:
            TypeError: If input data type is not valid
        """
        if isinstance(data_str, str):
            return unicodedata.normalize("NFKD", data_str)
        elif isinstance(data_str, list):
            return list(map(lambda s: unicodedata.normalize("NFKD", s), data_str))
        else:
            raise TypeError("Invalid data type")

    @staticmethod
    def MnemonicToList(mnemonic: Union[str, List[str]]) -> List[str]:
        """ Convert a mnemonic to list.

        Args:
            mnemonic (str or list): Mnemonic

        Returns:
            list: Mnemonic list
        """
        return mnemonic.split(" ") if not isinstance(mnemonic, list) else mnemonic

    @staticmethod
    def MnemonicToString(mnemonic: Union[str, List[str]]) -> str:
        """ Convert a mnemonic to string.

        Args:
            mnemonic (str or list): Mnemonic

        Returns:
            str: Mnemonic string
        """
        return " ".join(mnemonic) if isinstance(mnemonic, list) else mnemonic
