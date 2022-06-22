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

"""Module for Electrum old mnemonic seed generation."""

# Imports
from typing import Union
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic import ElectrumOldLanguages
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic_decoder import ElectrumOldMnemonicDecoder
from bip_utils.utils.misc import AlgoUtils, BytesUtils, CryptoUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumOldSeedGeneratorConst:
    """Class container for Electrum old seed generator constants."""

    # Number of hash iteration
    HASH_ITR_NUM: int = 100000


class ElectrumOldSeedGenerator:
    """
    Electrum seed generator class (old).
    It generates the seed from a mnemonic.
    """

    m_seed: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 lang: ElectrumOldLanguages = ElectrumOldLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object) : Mnemonic
            lang (ElectrumLanguages, optional): Language (default: English)

        Raises:
            ValueError: If the mnemonic is not valid
        """
        entropy_bytes = ElectrumOldMnemonicDecoder(lang).Decode(mnemonic)
        # Compute the seed only once
        self.m_seed = self.__GenerateSeed(entropy_bytes)

    def Generate(self) -> bytes:
        """
        Generate seed.
        There is no really need of this method, since the seed is always the same, but it's
        kept in this way to have the same usage of Bip39/Substrate seed generator
        (i.e. ElectrumOldSeedGenerator(mnemonic).Generate() ).

        Returns:
            bytes: Generated seed
        """
        return self.m_seed

    @staticmethod
    def __GenerateSeed(entropy_bytes: bytes) -> bytes:
        """
        Generate seed from entropy bytes.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            bytes: Generated seed
        """
        entropy_hex = AlgoUtils.Encode(BytesUtils.ToHexString(entropy_bytes))
        x = entropy_hex
        for _ in range(ElectrumOldSeedGeneratorConst.HASH_ITR_NUM):
            x = CryptoUtils.Sha256(x + entropy_hex)
        return x
