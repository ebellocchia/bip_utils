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

"""Module for Electrum mnemonic generation."""

# Imports
from bip_utils.bip.bip39 import Bip39MnemonicValidator
from bip_utils.electrum.mnemonic.electrum_mnemonic import ElectrumMnemonicConst, ElectrumMnemonicTypes
from bip_utils.electrum.old_mnemonic import ElectrumOldMnemonicValidator
from bip_utils.utils.misc import BytesUtils, CryptoUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumMnemonicUtilsConst:
    """Class container for Electrum mnemonic utility constants."""

    # HMAC key
    HMAC_KEY: bytes = b"Seed version"


class ElectrumMnemonicUtils:
    """Class container for Electrum mnemonic utility functions."""

    @staticmethod
    def IsValidMnemonic(mnemonic: Mnemonic) -> bool:
        """
        Get if the specified mnemonic is valid (any type).

        Args:
            mnemonic (Mnemonic): Mnemonic

        Returns:
            bool: True if valid, false otherwise
        """
        if ElectrumMnemonicUtils.__IsBip39OrOldMnemonic(mnemonic):
            return False
        # Test all types
        for mnemonic_type in ElectrumMnemonicTypes:
            if ElectrumMnemonicUtils.__IsType(mnemonic, mnemonic_type):
                return True
        return False

    @staticmethod
    def IsValidMnemonicType(mnemonic: Mnemonic,
                            mnemonic_type: ElectrumMnemonicTypes) -> bool:
        """
        Get if the specified mnemonic is valid.

        Args:
            mnemonic (Mnemonic)                  : Mnemonic
            mnemonic_type (ElectrumMnemonicTypes): Mnemonic type

        Returns:
            bool: True if valid, false otherwise
        """
        if ElectrumMnemonicUtils.__IsBip39OrOldMnemonic(mnemonic):
            return False
        return ElectrumMnemonicUtils.__IsType(mnemonic, mnemonic_type)

    @staticmethod
    def __IsBip39OrOldMnemonic(mnemonic: Mnemonic) -> bool:
        """
        Get if the specified mnemonic is a valid BIP39 or old Electrum mnemonic.

        Args:
            mnemonic (Mnemonic): Mnemonic

        Returns:
            bool: True if valid, false otherwise
        """
        return Bip39MnemonicValidator().IsValid(mnemonic) or ElectrumOldMnemonicValidator().IsValid(mnemonic)

    @staticmethod
    def __IsType(mnemonic: Mnemonic,
                 mnemonic_type: ElectrumMnemonicTypes) -> bool:
        """
        Get if the specified mnemonic is of the specified type.

        Args:
            mnemonic (Mnemonic)                  : Mnemonic
            mnemonic_type (ElectrumMnemonicTypes): Mnemonic type

        Returns:
            bool: True if valid, false otherwise
        """
        h = CryptoUtils.HmacSha512(ElectrumMnemonicUtilsConst.HMAC_KEY, mnemonic.ToStr())
        return BytesUtils.ToHexString(h).startswith(ElectrumMnemonicConst.TYPE_TO_PREFIX[mnemonic_type])
