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
Module for SLIP39 mnemonic encoding.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from bip_utils.slip.slip39.slip39_mnemonic import Slip39Languages, Slip39Mnemonic, Slip39MnemonicConst
from bip_utils.slip.slip39.slip39_mnemonic_utils import Slip39MnemonicUtils, Slip39Rs1024, Slip39WordsListGetter
from bip_utils.slip.slip39.slip39_share import Slip39Share
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicWordsList


class Slip39MnemonicEncoder:
    """
    SLIP39 mnemonic encoder class.
    It encodes a share to a mnemonic.
    """

    m_words_list: MnemonicWordsList

    def __init__(self) -> None:
        """Construct class."""
        self.m_words_list = Slip39WordsListGetter.Instance().GetByLanguage(Slip39Languages.ENGLISH)

    def Encode(self,
               share: Slip39Share) -> Mnemonic:
        """
        Encode a share to mnemonic.

        Args:
            share (Slip39Share object): Share

        Returns:
            Mnemonic object: Encoded mnemonic

        Raises:
            ValueError: If the share is not valid
        """
        self.__ValidateShare(share)

        id_ext_iter_exp = ((share.identifier << (Slip39MnemonicConst.ITER_EXP_BIT_LEN + 1))
                           | (int(share.extendable) << Slip39MnemonicConst.ITER_EXP_BIT_LEN)
                           | share.iteration_exponent)
        share_params = 0
        for param in (share.group_index,
                      share.group_threshold - 1,
                      share.group_count - 1,
                      share.member_index,
                      share.member_threshold - 1):
            share_params = (share_params << Slip39MnemonicConst.PARAM_BIT_LEN) | param

        data = (
            Slip39MnemonicUtils.IntToWordIndexes(id_ext_iter_exp, Slip39MnemonicConst.ID_EXT_ITER_EXP_WORDS_NUM)
            + Slip39MnemonicUtils.IntToWordIndexes(share_params, Slip39MnemonicConst.SHARE_PARAMS_WORDS_NUM)
            + Slip39MnemonicUtils.IntToWordIndexes(BytesUtils.ToInteger(share.value),
                                                   Slip39MnemonicUtils.ValueWordsNum(len(share.value)))
        )
        checksum = Slip39Rs1024.Compute(Slip39MnemonicUtils.ChecksumCustomString(share.extendable), data)

        return Slip39Mnemonic.FromList([self.m_words_list.GetWordAtIdx(idx) for idx in data + checksum])

    @staticmethod
    def __ValidateShare(share: Slip39Share) -> None:
        """
        Validate a share.

        Args:
            share (Slip39Share object): Share

        Raises:
            ValueError: If the share is not valid
        """
        max_shares_num = Slip39MnemonicConst.MAX_SHARES_NUM
        if not 0 <= share.identifier < 2 ** Slip39MnemonicConst.ID_BIT_LEN:
            raise ValueError(f"Invalid identifier ({share.identifier})")
        if not 0 <= share.iteration_exponent < 2 ** Slip39MnemonicConst.ITER_EXP_BIT_LEN:
            raise ValueError(f"Invalid iteration exponent ({share.iteration_exponent})")
        if not 1 <= share.group_threshold <= share.group_count <= max_shares_num:
            raise ValueError(f"Invalid group threshold ({share.group_threshold}) or count ({share.group_count})")
        if not 0 <= share.group_index < share.group_count:
            raise ValueError(f"Invalid group index ({share.group_index})")
        if not 1 <= share.member_threshold <= max_shares_num:
            raise ValueError(f"Invalid member threshold ({share.member_threshold})")
        if not 0 <= share.member_index < max_shares_num:
            raise ValueError(f"Invalid member index ({share.member_index})")
        if len(share.value) < Slip39MnemonicConst.MIN_SECRET_BYTE_LEN or len(share.value) % 2 != 0:
            raise ValueError(f"Invalid share value length ({len(share.value)})")
