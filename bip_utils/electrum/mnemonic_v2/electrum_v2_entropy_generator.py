# Copyright (c) 2022 Emanuele Bellocchia
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

"""Module for Electrum v2 mnemonic entropy generation."""

# Imports
import math
from enum import IntEnum, unique
from typing import List, Union

from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import ElectrumV2MnemonicConst
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import EntropyGenerator


@unique
class ElectrumV2EntropyBitLen(IntEnum):
    """Enumerative for Electrum entropy bit lengths (v2)."""

    BIT_LEN_132 = 132
    BIT_LEN_264 = 264


class ElectrumV2EntropyGeneratorConst:
    """Class container for Electrum entropy generator constants (v2)."""

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[ElectrumV2EntropyBitLen] = [
        ElectrumV2EntropyBitLen.BIT_LEN_132,
        ElectrumV2EntropyBitLen.BIT_LEN_264,
    ]


class ElectrumV2EntropyGenerator(EntropyGenerator):
    """
    Electrum entropy generator class (v2).
    It generates random entropy bytes.
    """

    def __init__(self,
                 bit_len: Union[int, ElectrumV2EntropyBitLen]) -> None:
        """
        Construct class.

        Args:
            bit_len (int or ElectrumV2EntropyBitLen): Entropy length in bits

        Raises:
            ValueError: If the bit length is not valid
        """
        if not self.IsValidEntropyBitLen(bit_len):
            raise ValueError(f"Entropy bit length is not valid ({bit_len})")
        super().__init__(bit_len)

    @staticmethod
    def IsValidEntropyBitLen(bit_len: int) -> bool:
        """
        Get if the specified entropy bit length is valid.

        Args:
            bit_len (int): Entropy length in bits

        Returns:
            bool: True if valid, false otherwise
        """
        # Because of the mnemonic encoding algorithm used by Electrum, the bit length shall be greater than the
        # maximum one minus the bit length of a single word, in order to "have space" for the last mnemonic word
        for entropy_bit_len in ElectrumV2EntropyGeneratorConst.ENTROPY_BIT_LEN:
            if entropy_bit_len - ElectrumV2MnemonicConst.WORD_BIT_LEN <= bit_len <= entropy_bit_len:
                return True
        return False

    @staticmethod
    def IsValidEntropyByteLen(byte_len: int) -> bool:
        """
        Get if the specified entropy byte length is valid.

        Args:
            byte_len (int): Entropy length in bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return ElectrumV2EntropyGenerator.IsValidEntropyBitLen(byte_len * 8)

    @staticmethod
    def AreEntropyBitsEnough(entropy: Union[bytes, int]) -> bool:
        """
        Get if the entropy bits are enough to generate a valid mnemonic.

        Args:
            entropy (bytes or int): Entropy

        Returns:
            bool: True if enough, false otherwise
        """
        if isinstance(entropy, bytes):
            entropy = BytesUtils.ToInteger(entropy)
        entropy_bit_len = 0 if entropy <= 0 else math.floor(math.log(entropy, 2))
        return ElectrumV2EntropyGenerator.IsValidEntropyBitLen(entropy_bit_len)
