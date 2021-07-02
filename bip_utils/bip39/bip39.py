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
import os
import unicodedata
from abc import ABC, abstractmethod
from enum import auto, Enum, IntEnum, unique
from typing import Dict, List, Optional, Union
from bip_utils.bip39.bip39_ex import Bip39InvalidFileError, Bip39ChecksumError
from bip_utils.utils import AlgoUtils, ConvUtils, CryptoUtils


@unique
class Bip39WordsNum(IntEnum):
    """ Enumerative for BIP-0039 words number. """

    WORDS_NUM_12 = 12,
    WORDS_NUM_15 = 15,
    WORDS_NUM_18 = 18,
    WORDS_NUM_21 = 21,
    WORDS_NUM_24 = 24,


@unique
class Bip39EntropyBitLen(IntEnum):
    """ Enumerative for BIP-0039 entropy bit lengths. """

    BIT_LEN_128 = 128,
    BIT_LEN_160 = 160,
    BIT_LEN_192 = 192,
    BIT_LEN_224 = 224,
    BIT_LEN_256 = 256,


@unique
class Bip39Languages(Enum):
    """ Enumerative for BIP-0039 languages. """

    ENGLISH = auto(),
    ITALIAN = auto(),
    FRENCH = auto(),
    SPANISH = auto(),
    PORTUGUESE = auto(),
    CZECH = auto(),
    CHINESE_SIMPLIFIED = auto(),
    CHINESE_TRADITIONAL = auto(),
    KOREAN = auto(),


class Bip39Const:
    """ Class container for BIP39 constants. """

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[Bip39EntropyBitLen] = [
            Bip39EntropyBitLen.BIT_LEN_128,
            Bip39EntropyBitLen.BIT_LEN_160,
            Bip39EntropyBitLen.BIT_LEN_192,
            Bip39EntropyBitLen.BIT_LEN_224,
            Bip39EntropyBitLen.BIT_LEN_256,
        ]

    # Accepted mnemonic word lengths
    MNEMONIC_WORD_LEN: List[Bip39WordsNum] = [
            Bip39WordsNum.WORDS_NUM_12,
            Bip39WordsNum.WORDS_NUM_15,
            Bip39WordsNum.WORDS_NUM_18,
            Bip39WordsNum.WORDS_NUM_21,
            Bip39WordsNum.WORDS_NUM_24,
        ]

    # Language files
    LANGUAGE_FILES: Dict[Bip39Languages, str] = {
            Bip39Languages.ENGLISH: "bip39_words/english.txt",
            Bip39Languages.ITALIAN: "bip39_words/italian.txt",
            Bip39Languages.FRENCH: "bip39_words/french.txt",
            Bip39Languages.SPANISH: "bip39_words/spanish.txt",
            Bip39Languages.PORTUGUESE: "bip39_words/portuguese.txt",
            Bip39Languages.CZECH: "bip39_words/czech.txt",
            Bip39Languages.CHINESE_SIMPLIFIED: "bip39_words/chinese_simplified.txt",
            Bip39Languages.CHINESE_TRADITIONAL: "bip39_words/chinese_traditional.txt",
            Bip39Languages.KOREAN: "bip39_words/korean.txt",
        }

    # Total number of words
    WORDS_LIST_NUM: int = 2048
    # Bits of a single word
    WORD_BITS: int = 11

    # Salt modifier for seed generation
    SEED_SALT_MOD: str = "mnemonic"
    # PBKDF2 round for seed generation
    SEED_PBKDF2_ROUNDS: int = 2048
    # Seed length in bytes
    SEED_BYTE_LEN: int = 64


class Bip39Utils:
    """ Class container for BIP39 utility functions. """

    @staticmethod
    def NormalizeString(data_str: Union[str, List[str]]) -> Union[str, List[str]]:
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


class Bip39EntropyGenerator:
    """ Entropy generator class. It generates random entropy bytes with the specified length. """

    def __init__(self,
                 bits_len: Union[int, Bip39EntropyBitLen]) -> None:
        """ Construct class by specifying the bits length.

        Args:
            bits_len (int or Bip39EntropyBitLen): Entropy length in bits

        Raises:
            ValueError: If the bit length is not valid
        """
        if bits_len % 8 != 0:
            raise ValueError("Bit length not multiple of 8")

        self.m_bits_len = bits_len

    def Generate(self) -> bytes:
        """ Generate random entropy bytes with the length specified during construction.

        Returns:
            bytes: Generated entropy bytes
        """
        return os.urandom(self.m_bits_len // 8)


class MnemonicFileReader:
    """ Mnemonic file reader class. It reads the English BIP39 words list from a file """

    # Languages supporting binary search
    BIN_SEARCH_LANG: List[Bip39Languages] = [Bip39Languages.ENGLISH, Bip39Languages.ITALIAN,
                                             Bip39Languages.PORTUGUESE, Bip39Languages.CZECH]

    def __init__(self,
                 lang: Bip39Languages = Bip39Languages.ENGLISH) -> None:
        """ Construct class by reading the words list from file.

        Args:
            lang (Bip39Languages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            Bip39InvalidFileError: If loaded words list length is not 2048
        """

        if not isinstance(lang, Bip39Languages):
            raise TypeError("Language is not an enumerative of Bip39Languages")

        self.m_lang = lang
        self.__LoadFile(lang)

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

        # Use binary search when possible
        if self.m_lang in self.BIN_SEARCH_LANG:
            idx = AlgoUtils.BinarySearch(self.m_words_list, word)
        else:
            idx = self.m_words_list.index(word)
        # Check index
        if idx == -1:
            raise ValueError("Word '%s' is not existent in word list" % word)

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

    def __LoadFile(self,
                   lang: Bip39Languages) -> None:
        """ Load mnemonic file.

        Args:
            lang (Bip39Languages): Language

        Raises:
            Bip39InvalidFileError: If loaded words list length is not 2048
        """

        # Get file path
        file_name = Bip39Const.LANGUAGE_FILES[lang]
        file_path = os.path.join(os.path.dirname(__file__), file_name)
        # Read file
        with open(file_path, "r", encoding="utf-8") as fin:
            self.m_words_list = [word.strip() for word in fin.readlines() if word.strip() != ""]

        # Check words list length
        if len(self.m_words_list) != Bip39Const.WORDS_LIST_NUM:
            raise Bip39InvalidFileError("Number of loaded words list (%d) is not valid" % len(self.m_words_list))


class Bip39MnemonicGenerator:
    """ BIP39 mnemonic generator class. It generates the mnemonic in according to BIP39.
    Mnemonic can be generated randomly or from a specified entropy.
    BIP-0039 specifications: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    """

    def __init__(self,
                 lang: Bip39Languages = Bip39Languages.ENGLISH) -> None:
        """ Construct class from language.

        Args:
            lang (Bip39Languages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            Bip39InvalidFileError: If loaded words list length is not 2048
        """
        self.m_mnemonic_reader = MnemonicFileReader(lang)

    def FromWordsNumber(self,
                        words_num: Union[int, Bip39WordsNum]) -> str:
        """ Generate mnemonic with the specified words number from random entropy.

        Args:
            words_num (int or Bip39WordsNum): Number of words (12, 15, 18, 21, 24)

        Returns:
            str: Generated mnemonic from random entropy

        Raises:
            ValueError: If words number is not valid
        """

        # Check words number
        if words_num not in Bip39Const.MNEMONIC_WORD_LEN:
            raise ValueError("Words number for mnemonic (%d) is not valid" % words_num)

        # Get entropy length in bit from words number
        entropy_bit_len = self.__EntropyBitLenFromWordsNum(words_num)
        # Generate entropy
        entropy_bytes = Bip39EntropyGenerator(entropy_bit_len).Generate()

        return self.FromEntropy(entropy_bytes)

    def FromEntropy(self,
                    entropy_bytes: bytes) -> str:
        """ Generate mnemonic from the specified entropy bytes.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 160, 192, 224, 256)

        Returns:
            str: Generated mnemonic from specified entropy

        Raises:
            ValueError: If entropy length is not valid
        """

        # Check entropy length in bits
        entropy_bit_len = len(entropy_bytes) * 8
        if entropy_bit_len not in Bip39Const.ENTROPY_BIT_LEN:
            raise ValueError("Entropy length in bits (%d) is not valid" % entropy_bit_len)

        # Compute entropy hash
        entropy_hash_bytes = CryptoUtils.Sha256(entropy_bytes)

        # Convert entropy to binary string
        entropy_bin = ConvUtils.BytesToBinaryStr(entropy_bytes, len(entropy_bytes) * 8)
        # Convert entropy hash to binary string
        entropy_hash_bin = ConvUtils.BytesToBinaryStr(entropy_hash_bytes, CryptoUtils.Sha256DigestSize() * 8)
        # Get checksum binary string
        checksum_bin = entropy_hash_bin[: len(entropy_bytes) // 4]

        # Create mnemonic entropy binary string by concatenating entropy and checksum, as specified in BIP39
        mnemonic_entropy_bin = entropy_bin + checksum_bin

        # Get mnemonic from entropy
        mnemonic = []
        for i in range(len(mnemonic_entropy_bin) // Bip39Const.WORD_BITS):
            # Get current word index
            word_idx = int(mnemonic_entropy_bin[i * Bip39Const.WORD_BITS: (i + 1) * Bip39Const.WORD_BITS], 2)
            # Get word at given index
            mnemonic.append(self.m_mnemonic_reader.GetWordAtIdx(word_idx))

        return Bip39Utils.MnemonicToString(mnemonic)

    @staticmethod
    def __EntropyBitLenFromWordsNum(words_num: int) -> int:
        """ Get entropy length from words number.

        Args:
            words_num (int): Words number

        Returns:
            int: Correspondent entropy length
        """
        return (words_num * Bip39Const.WORD_BITS) - (words_num // 3)


class Bip39MnemonicValidator:
    """ BIP39 mnemonic validator class. It validates a mnemonic string or list. """

    #
    # Public methods
    #

    def __init__(self,
                 mnemonic: Union[str, List[str]],
                 lang: Optional[Bip39Languages] = None) -> None:
        """ Construct the class from mnemonic.

        Args:
            mnemonic (str or list): Mnemonic
            lang (Bip39Languages, optional): Language, None for automatic detection
        """
        self.m_mnemonic = Bip39Utils.MnemonicToList(Bip39Utils.NormalizeString(mnemonic))
        self.m_mnemonic_reader = (self.__GetMnemonicReader(self.m_mnemonic)
                                  if lang is None
                                  else MnemonicFileReader(lang))

    def Validate(self) -> None:
        """ Validate the mnemonic specified at construction.

        Raises:
            ValueError: If mnemonic is not valid
            Bip39ChecksumError: If checksum is not valid
        """

        # Check language
        if self.m_mnemonic_reader is None:
            raise ValueError("Invalid language for mnemonic '%s'" % " ".join(self.m_mnemonic))

        # Get back mnemonic binary string
        mnemonic_bin = self.__GetMnemonicBinaryStr()

        # Verify checksum
        checksum = self.__GetChecksum(mnemonic_bin)
        comp_checksum = self.__ComputeChecksum(mnemonic_bin)

        if checksum != comp_checksum:
            raise Bip39ChecksumError("Invalid checksum when getting entropy (expected %s, got %s)" %
                                     (comp_checksum, checksum))

    def IsValid(self) -> bool:
        """ Get if the mnemonic specified at construction is valid.

        Returns:
            bool: True if valid, False otherwise
        """

        # Simply try to validate
        try:
            self.Validate()
            return True
        except (ValueError, Bip39ChecksumError):
            return False

    def GetEntropy(self) -> bytes:
        """Get entropy bytes from mnemonic.

        Returns:
            bytes: Entropy bytes corresponding to the mnemonic

        Raises:
            ValueError: If mnemonic is not valid
            Bip39ChecksumError: If checksum is not valid
        """

        # Validate mnemonic
        self.Validate()

        # Get entropy bytes from binary string
        return self.__GetEntropyBytes(self.__GetMnemonicBinaryStr())

    #
    # Private methods
    #

    def __GetMnemonicBinaryStr(self) -> str:
        """ Get mnemonic binary string from mnemonic string or list.

        Returns:
           str: Mnemonic binary string

        Raises:
            ValueError: If mnemonic is not valid
        """

        # Check mnemonic length
        if len(self.m_mnemonic) not in Bip39Const.MNEMONIC_WORD_LEN:
            raise ValueError("Mnemonic length (%d) is not valid" % len(self.m_mnemonic))

        # Convert each word to its index in binary format
        mnemonic_bin = map(lambda word: ConvUtils.IntegerToBinaryStr(self.m_mnemonic_reader.GetWordIdx(word),
                                                                     Bip39Const.WORD_BITS),
                           self.m_mnemonic)

        # Join the elements to get the complete binary string
        return "".join(mnemonic_bin)

    def __GetEntropyBytes(self,
                          mnemonic_bin_str: str) -> bytes:
        """ Get entropy from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           bytes: Entropy bytes
        """

        # Get checksum length
        checksum_len = self.__GetChecksumLen(mnemonic_bin_str)
        # Get back entropy binary string
        entropy_bin = mnemonic_bin_str[:-checksum_len]

        # Get entropy bytes from binary string
        return ConvUtils.BinaryStrToBytes(entropy_bin, checksum_len * 8)

    def __GetChecksum(self,
                      mnemonic_bin_str: str) -> str:
        """ Get checksum from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           str: Checksum binary string
        """
        return mnemonic_bin_str[-self.__GetChecksumLen(mnemonic_bin_str):]

    def __ComputeChecksum(self,
                          mnemonic_bin_str: str) -> str:
        """ Compute checksum from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           str: Computed checksum binary string
        """

        # Get entropy bytes
        entropy_bytes = self.__GetEntropyBytes(mnemonic_bin_str)
        # Convert entropy hash to binary string
        entropy_hash_bin = ConvUtils.BytesToBinaryStr(CryptoUtils.Sha256(entropy_bytes),
                                                      CryptoUtils.Sha256DigestSize() * 8)

        # Compute checksum
        checksum_bin = entropy_hash_bin[:self.__GetChecksumLen(mnemonic_bin_str)]

        return checksum_bin

    @staticmethod
    def __GetChecksumLen(mnemonic_bin_str: str) -> int:
        """ Get checksum length from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           int: Checksum length
        """
        return len(mnemonic_bin_str) // 33

    @staticmethod
    def __GetMnemonicReader(mnemonic: List[str]) -> Optional[MnemonicFileReader]:
        """ Automatically find the language of the specified mnemonic and
        get the correct MnemonicFileReader class for it.

        Args:
            mnemonic (list): List of words

        Returns:
           MnemonicFileReader: Mnemonic reader class for the found language, None if language is not found
        """

        for lang in Bip39Languages:
            # We search for each word because some languages have words in common (e.g. 'fatigue' both in English and French)
            # It's more time consuming, but considering only the first word can detect the wrong language sometimes
            try:
                mnemonic_reader = MnemonicFileReader(lang)
                for word in mnemonic:
                    mnemonic_reader.GetWordIdx(word)
                return mnemonic_reader
            except ValueError:
                continue

        return None


class IBip39SeedGenerator(ABC):
    """ BIP39 seed generator interface. """

    @abstractmethod
    def __init__(self,
                 mnemonic: Union[str, List[str]],
                 lang: Optional[Bip39Languages]) -> None:
        pass

    @abstractmethod
    def Generate(self,
                 passphrase: str) -> bytes:
        """ Generate the seed using the specified passphrase.

        Args:
            passphrase (str, optional): Passphrase, empty if not specified

        Returns:
            bytes: Generated seed
        """
        pass


class Bip39SeedGenerator(IBip39SeedGenerator):
    """ BIP39 seed generator class. It generates the seed from a mnemonic in according to BIP39. """

    def __init__(self,
                 mnemonic: Union[str, List[str]],
                 lang: Optional[Bip39Languages] = None) -> None:
        """ Construct the class from a specified mnemonic.

        Args:
            mnemonic (str or list): Mnemonic
            lang (Bip39Languages, optional): Language, None for automatic detection

        Raises:
            ValueError: If the mnemonic is not valid
        """

        # Make sure that the given mnemonic is valid
        Bip39MnemonicValidator(mnemonic, lang).Validate()

        self.m_mnemonic = Bip39Utils.MnemonicToString(Bip39Utils.NormalizeString(mnemonic))

    def Generate(self,
                 passphrase: str = "") -> bytes:
        """ Generate the seed using the specified passphrase.

        Args:
            passphrase (str, optional): Passphrase, empty if not specified

        Returns:
            bytes: Generated seed
        """

        # Get salt
        salt = Bip39Utils.NormalizeString(Bip39Const.SEED_SALT_MOD + passphrase)
        # Compute key
        key = CryptoUtils.Pbkdf2HmacSha512(self.m_mnemonic,
                                           salt,
                                           Bip39Const.SEED_PBKDF2_ROUNDS)

        return key[:Bip39Const.SEED_BYTE_LEN]


class Bip39SubstrateSeedGenerator(IBip39SeedGenerator):
    """ BIP39 substrate seed generator class. It implements a variant for generating seed introduced by Polkadot.
    Reference: https://github.com/paritytech/substrate-bip39
    """

    def __init__(self,
                 mnemonic: Union[str, List[str]],
                 lang: Optional[Bip39Languages] = None) -> None:
        """ Construct the class from a specified mnemonic.

        Args:
            mnemonic (str or list): Mnemonic
            lang (Bip39Languages, optional): Language, None for automatic detection

        Raises:
            ValueError: If the mnemonic is not valid
        """

        # Make sure that the given mnemonic is valid
        mnemonic_validator = Bip39MnemonicValidator(mnemonic, lang)
        mnemonic_validator.Validate()

        self.m_entropy = mnemonic_validator.GetEntropy()

    def Generate(self,
                 passphrase: str = "") -> bytes:
        """ Generate the seed using the specified passphrase.

        Args:
            passphrase (str, optional): Passphrase, empty if not specified

        Returns:
            bytes: Generated seed
        """

        # Get salt
        salt = Bip39Utils.NormalizeString(Bip39Const.SEED_SALT_MOD + passphrase)
        # Compute key
        key = CryptoUtils.Pbkdf2HmacSha512(self.m_entropy,
                                           salt,
                                           Bip39Const.SEED_PBKDF2_ROUNDS)

        return key[:Bip39Const.SEED_BYTE_LEN]
