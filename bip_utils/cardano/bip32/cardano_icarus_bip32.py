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

"""Module for keys derivation based for Cardano Icarus."""

# Imports
from typing import Type

from bip_utils.bip.bip32 import Bip32KholawEd25519, IBip32MstKeyGenerator
from bip_utils.cardano.bip32.cardano_icarus_mst_key_generator import CardanoIcarusMstKeyGenerator


class CardanoIcarusBip32(Bip32KholawEd25519):
    """
    Cardano Icarus BIP32 class.
    It allows master keys generation and keys derivation for Cardano Icarus.
    Derivation based on BIP32 ed25519 Khovratovich/Law with a different algorithm for master key generation.
    """

    @staticmethod
    def _MasterKeyGenerator() -> Type[IBip32MstKeyGenerator]:
        """
        Return the master key generator class.

        Returns:
            IBip32MstKeyGenerator class: Master key generator class
        """
        return CardanoIcarusMstKeyGenerator
