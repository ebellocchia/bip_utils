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

"""Module for Electrum old mnemonic validation."""

# Imports
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic import ElectrumOldLanguages
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic_decoder import ElectrumOldMnemonicDecoder
from bip_utils.utils.mnemonic import MnemonicValidator


class ElectrumOldMnemonicValidator(MnemonicValidator):
    """
    Electrum old mnemonic validator class.
    It validates a mnemonic phrase.
    """

    m_mnemonic_decoder: ElectrumOldMnemonicDecoder

    def __init__(self,
                 lang: ElectrumOldLanguages = ElectrumOldLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (AlgorandLanguages): Language
        """
        super().__init__(ElectrumOldMnemonicDecoder(lang))
