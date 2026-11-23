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
Module for SLIP39 mnemonic decoding.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from typing import Union

from bip_utils.slip.slip39.slip39_mnemonic import Slip39Languages, Slip39Mnemonic, Slip39MnemonicConst
from bip_utils.slip.slip39.slip39_mnemonic_utils import Slip39MnemonicUtils, Slip39Rs1024, Slip39WordsListGetter
from bip_utils.slip.slip39.slip39_share import Slip39Share
from bip_utils.utils.misc import IntegerUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicChecksumError, MnemonicWordsList


class Slip39MnemonicDecoder:
    """
    SLIP39 mnemonic decoder class.
    It decodes a mnemonic to a share.
    """

    m_words_list: MnemonicWordsList

    def __init__(self) -> None:
        """Construct class."""
        self.m_words_list = Slip39WordsListGetter.Instance().GetByLanguage(Slip39Languages.ENGLISH)

    def Decode(self,
               mnemonic: Union[str, Mnemonic]) -> Slip39Share:
        """
        Decode a mnemonic to a share.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            Slip39Share object: Decoded share

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic = Slip39Mnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check length and padding
        words_num = mnemonic.WordsCount()
        if words_num < Slip39MnemonicConst.MIN_WORDS_NUM:
            raise ValueError(f"Invalid words number ({words_num})")
        padding_bit_len = (Slip39MnemonicConst.WORD_BIT_LEN * (words_num - Slip39MnemonicConst.METADATA_WORDS_NUM)) % 16
        if padding_bit_len > Slip39MnemonicConst.MAX_PADDING_BIT_LEN:
            raise ValueError(f"Invalid words number ({words_num})")

        word_indexes = [self.m_words_list.GetWordIdx(word) for word in mnemonic.ToList()]

        # Check checksum (the customization string depends on the extendable flag)
        id_ext_iter_exp = Slip39MnemonicUtils.WordIndexesToInt(
            word_indexes[:Slip39MnemonicConst.ID_EXT_ITER_EXP_WORDS_NUM]
        )
        extendable = bool((id_ext_iter_exp >> Slip39MnemonicConst.ITER_EXP_BIT_LEN) & 1)
        if not Slip39Rs1024.Verify(Slip39MnemonicUtils.ChecksumCustomString(extendable), word_indexes):
            raise MnemonicChecksumError("Invalid checksum")

        # Get share value, padding bits shall be zero
        value_word_indexes = word_indexes[Slip39MnemonicConst.ID_EXT_ITER_EXP_WORDS_NUM
                                          + Slip39MnemonicConst.SHARE_PARAMS_WORDS_NUM:
                                          -Slip39MnemonicConst.CHECKSUM_WORDS_NUM]
        value_int = Slip39MnemonicUtils.WordIndexesToInt(value_word_indexes)
        value_byte_len = (Slip39MnemonicConst.WORD_BIT_LEN * len(value_word_indexes) - padding_bit_len) // 8
        if value_int >> (value_byte_len * 8) != 0:
            raise ValueError("Invalid share value padding")

        # Get share parameters
        share_params = Slip39MnemonicUtils.WordIndexesToInt(
            word_indexes[Slip39MnemonicConst.ID_EXT_ITER_EXP_WORDS_NUM:
                         Slip39MnemonicConst.ID_EXT_ITER_EXP_WORDS_NUM + Slip39MnemonicConst.SHARE_PARAMS_WORDS_NUM]
        )
        param_mask = (1 << Slip39MnemonicConst.PARAM_BIT_LEN) - 1
        group_index, group_threshold, group_count, member_index, member_threshold = [
            (share_params >> (Slip39MnemonicConst.PARAM_BIT_LEN * (4 - i))) & param_mask for i in range(5)
        ]
        if group_threshold > group_count:
            raise ValueError(f"Group threshold ({group_threshold + 1}) is greater than group count ({group_count + 1})")

        return Slip39Share(
            identifier=id_ext_iter_exp >> (Slip39MnemonicConst.ITER_EXP_BIT_LEN + 1),
            extendable=extendable,
            iteration_exponent=id_ext_iter_exp & ((1 << Slip39MnemonicConst.ITER_EXP_BIT_LEN) - 1),
            group_index=group_index,
            group_threshold=group_threshold + 1,
            group_count=group_count + 1,
            member_index=member_index,
            member_threshold=member_threshold + 1,
            value=IntegerUtils.ToBytes(value_int, bytes_num=value_byte_len),
        )
