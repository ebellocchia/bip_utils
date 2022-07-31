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

"""Module for Cardano Byron legacy mnemonic seed generation (old Daedalus version)."""

# Imports
from typing import Optional, Union
import cbor2
from bip_utils.bip.bip39 import Bip39Languages, Bip39MnemonicDecoder
from bip_utils.utils.misc import CryptoUtils
from bip_utils.utils.mnemonic import Mnemonic


class CardanoByronOldGeneratorConst:
    """Class container for Cardano Byron legacy seed generator constants."""

    # Blake2b length in bytes
    BLAKE2B_BYTE_LEN: int = 32


class CardanoByronLegacySeedGenerator:
    """
    Cardano Byron legacy seed generator class.
    It generates seeds from a BIP39 mnemonic for Cardano Byron (legacy).
    """

    m_ser_seed_bytes: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 lang: Optional[Bip39Languages] = None) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic
            lang (Bip39Languages, optional)  : Language, None for automatic detection

        Raises:
            ValueError: If the mnemonic is not valid
        """
        ser_entropy_bytes = cbor2.dumps(Bip39MnemonicDecoder(lang).Decode(mnemonic))
        self.m_seed_bytes = CryptoUtils.Blake2b(ser_entropy_bytes,
                                                CardanoByronOldGeneratorConst.BLAKE2B_BYTE_LEN)

    def Generate(self) -> bytes:
        """
        Generate seed. The seed is simply the entropy bytes in Cardano case.
        There is no really need of this method, since the seed is always the same, but it's
        kept in this way to have the same usage of Bip39/Substrate seed generator
        (i.e. CardanoSeedGenerator(mnemonic).Generate() ).

        Returns:
            bytes: Generated seed
        """
        return self.m_seed_bytes
