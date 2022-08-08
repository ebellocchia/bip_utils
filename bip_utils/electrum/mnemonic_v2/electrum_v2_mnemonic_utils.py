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

"""Module for Electrum v2 mnemonic generation."""

# Imports
from typing import Optional

from bip_utils.bip.bip39 import Bip39MnemonicValidator
from bip_utils.electrum.mnemonic_v1 import ElectrumV1MnemonicValidator
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import ElectrumV2MnemonicConst, ElectrumV2MnemonicTypes
from bip_utils.utils.crypto import HmacSha512
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumV2MnemonicUtilsConst:
    """Class container for Electrum v2 mnemonic utility constants."""

    # HMAC key
    HMAC_KEY: bytes = b"Seed version"


class ElectrumV2MnemonicUtils:
    """Class container for Electrum v2 mnemonic utility functions."""

    @staticmethod
    def IsValidMnemonic(mnemonic: Mnemonic,
                        mnemonic_type: Optional[ElectrumV2MnemonicTypes] = None) -> bool:
        """
        Get if the specified mnemonic is valid.

        Args:
            mnemonic (Mnemonic)                    : Mnemonic
            mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type

        Returns:
            bool: True if valid, false otherwise
        """
        if ElectrumV2MnemonicUtils.__IsBip39OrV1Mnemonic(mnemonic):
            return False
        return (ElectrumV2MnemonicUtils.__IsType(mnemonic, mnemonic_type)
                if mnemonic_type is not None
                else ElectrumV2MnemonicUtils.__IsAnyType(mnemonic))

    @staticmethod
    def __IsBip39OrV1Mnemonic(mnemonic: Mnemonic) -> bool:
        """
        Get if the specified mnemonic is a valid BIP39 or v1 Electrum mnemonic.

        Args:
            mnemonic (Mnemonic): Mnemonic

        Returns:
            bool: True if valid, false otherwise
        """
        return Bip39MnemonicValidator().IsValid(mnemonic) or ElectrumV1MnemonicValidator().IsValid(mnemonic)

    @staticmethod
    def __IsAnyType(mnemonic: Mnemonic) -> bool:
        """
        Get if the specified mnemonic is of any valid type.

        Args:
            mnemonic (Mnemonic): Mnemonic

        Returns:
            bool: True if valid, false otherwise
        """
        h = HmacSha512.QuickDigest(ElectrumV2MnemonicUtilsConst.HMAC_KEY, mnemonic.ToStr())
        for mnemonic_type in ElectrumV2MnemonicTypes:
            if BytesUtils.ToHexString(h).startswith(ElectrumV2MnemonicConst.TYPE_TO_PREFIX[mnemonic_type]):
                return True
        return False

    @staticmethod
    def __IsType(mnemonic: Mnemonic,
                 mnemonic_type: ElectrumV2MnemonicTypes) -> bool:
        """
        Get if the specified mnemonic is of the specified type.

        Args:
            mnemonic (Mnemonic)                    : Mnemonic
            mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type

        Returns:
            bool: True if valid, false otherwise
        """
        h = HmacSha512.QuickDigest(ElectrumV2MnemonicUtilsConst.HMAC_KEY, mnemonic.ToStr())
        return BytesUtils.ToHexString(h).startswith(ElectrumV2MnemonicConst.TYPE_TO_PREFIX[mnemonic_type])
