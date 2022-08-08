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

"""Module for Electrum v1 mnemonic seed generation."""

# Imports
from typing import Optional, Union

from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic import ElectrumV1Languages
from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder import ElectrumV1MnemonicDecoder
from bip_utils.utils.crypto import Sha256
from bip_utils.utils.misc import AlgoUtils, BytesUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumV1SeedGeneratorConst:
    """Class container for Electrum v1 seed generator constants."""

    # Number of hash iteration
    HASH_ITR_NUM: int = 10**5


class ElectrumV1SeedGenerator:
    """
    Electrum seed generator class (v1).
    It generates the seed from a mnemonic.
    """

    m_seed: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 lang: Optional[ElectrumV1Languages] = ElectrumV1Languages.ENGLISH) -> None:
        """
        Construct class.
        Language is set to English by default because Electrum v1 mnemonic only support one language,
        so it's useless (and slower) to automatically detect the language.

        Args:
            mnemonic (str or Mnemonic object)   : Mnemonic
            lang (ElectrumV1Languages, optional): Language, None for automatic detection

        Raises:
            ValueError: If the mnemonic is not valid
        """
        entropy_bytes = ElectrumV1MnemonicDecoder(lang).Decode(mnemonic)
        # Compute the seed only once
        self.m_seed = self.__GenerateSeed(entropy_bytes)

    def Generate(self) -> bytes:
        """
        Generate seed.
        There is no really need of this method, since the seed is always the same, but it's
        kept in this way to have the same usage of Bip39/Substrate seed generator
        (i.e. ElectrumV1SeedGenerator(mnemonic).Generate() ).

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
        h = entropy_hex
        for _ in range(ElectrumV1SeedGeneratorConst.HASH_ITR_NUM):
            h = Sha256.QuickDigest(h + entropy_hex)
        return h
