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
from __future__ import annotations
from typing import List
from bip_utils.utils.misc.conversion import AlgoUtils


class Mnemonic:
    """ Mnemonic class. It represents a generic mnemonic phrase.
    It acts as a simple container with some helper functions, so it doesn't validate the given mnemonic.
    """

    @classmethod
    def FromString(cls,
                   mnemonic_str: str) -> Mnemonic:
        """ Create a class from mnemonic string.

        Args:
            mnemonic_str (str): Mnemonic string

        Returns:
            Mnemonic: Mnemonic object
        """
        return cls.FromList(mnemonic_str.split(" "))

    @classmethod
    def FromList(cls,
                 mnemonic_list: List[str]) -> Mnemonic:
        """ Create a class from mnemonic list.

        Args:
            mnemonic_list (list): Mnemonic list

        Returns:
            Mnemonic: Mnemonic object
        """
        return cls(mnemonic_list)

    def __init__(self,
                 mnemonic_list: List[str]) -> None:
        """ Construct class.

        Args:
            mnemonic_list (list): Mnemonic list
        """
        self.m_mnemonic_list = mnemonic_list

    def WordsCount(self) -> int:
        """ Get the words count.

        Returns:
            int: Words count
        """
        return len(self.m_mnemonic_list)

    def ToList(self) -> List[str]:
        """ Get the mnemonic as a list.

        Returns:
            list: Mnemonic as a list
        """
        return self.m_mnemonic_list

    def ToStr(self) -> str:
        """ Get the mnemonic as a string.

        Returns:
            str: Mnemonic as a string
        """
        return " ".join(self.m_mnemonic_list)

    def __str__(self) -> str:
        """ Get the mnemonic as a string.

        Returns:
            str: Mnemonic as a string
        """
        return self.ToStr()


class MnemonicWordsList:
    """ Mnemonic words list class. """

    def __init__(self,
                 words_list: List[str]) -> None:
        """ Construct class by reading the words list from file.

        Args:
            words_list (list): Words list
        """
        self.m_words_list = words_list
        self.m_use_bin_search = False

    def UseBinarySearch(self,
                        flag: bool) -> None:
        """ Set the usage of binary search.

        Args:
            flag (bool): True to use binary search, false otherwise
        """
        self.m_use_bin_search = flag

    def GetWordIdx(self,
                   word: str) -> int:
        """ Get the index of the specified word, by searching it in the list.

        Args:
            word (str): Word to be searched

        Returns:
            int: Word index

        Raises:
            ValueError: If the word is not found
        """

        # Use binary search if possible
        if self.m_use_bin_search:
            idx = AlgoUtils.BinarySearch(self.m_words_list, word)
            if idx == -1:
                raise ValueError(f"Word '{word}' is not existent in word list")
        else:
            idx = self.m_words_list.index(word)

        return idx

    def GetWordAtIdx(self,
                     word_idx: int) -> str:
        """ Get the word at the specified index.

        Args:
            word_idx (int): Word index

        Returns:
            str: Word at the specified index
        """
        return self.m_words_list[word_idx]


class MnemonicWordsListFileReader:
    """ Mnemonic words list file reader class. It reads the words list from a file. """

    @staticmethod
    def LoadFile(file_path: str,
                 words_num: int) -> MnemonicWordsList:
        """ Load words list file correspondent to the specified language.

        Args:
            file_path (str): File name
            words_num (int): Number of expected words

        Returns:
            MnemonicWordsList: MnemonicWordsList object

        Raises:
            ValueError: If loaded words list is not valid
        """

        # Read file
        with open(file_path, "r", encoding="utf-8") as fin:
            words_list = [word.strip() for word in fin.readlines() if word.strip() != ""]

        # Check words list count
        if len(words_list) != words_num:
            raise ValueError(f"Number of loaded words list ({len(words_list)}) is not valid")

        return MnemonicWordsList(words_list)


class MnemonicWordsListGetterBase:
    """ Mnemonic words list getter base class. """

    # Global instance
    __instance = None

    def __init__(self):
        """ Construct class. """
        self.m_words_lists = {}

    @staticmethod
    def _LoadWordsList(file_name: str,
                       words_num: int,
                       bin_search: bool) -> MnemonicWordsList:
        """ Load words list.

        Args:
            file_name (str)  : File name
            words_num (int)  : Number of expected words
            bin_search (bool): Binary search flag

        Returns:
            MnemonicWordsList object: MnemonicWordsList object

        Raises:
            ValueError: If loaded words list is not valid
        """
        words_list = MnemonicWordsListFileReader.LoadFile(file_name, words_num)
        words_list.UseBinarySearch(bin_search)

        return words_list

    @classmethod
    def Instance(cls) -> MnemonicWordsListGetterBase:
        """ Get the global class instance.

        Returns:
            MnemonicWordsListGetterBase object: MnemonicWordsListGetterBase object
        """
        if cls.__instance is None:
            cls.__instance = cls()
        return cls.__instance
