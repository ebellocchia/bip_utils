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

"""Module for Monero Polyseed mnemonic encryption."""

# Imports
import unicodedata

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import MoneroPolyseedMnemonicConst
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_utils import (
    MoneroPolyseedDecodedData,
    MoneroPolyseedGf,
    MoneroPolyseedMnemonicUtils,
)
from bip_utils.utils.crypto import Pbkdf2HmacSha256


class MoneroPolyseedMnemonicEncrypter:
    """
    Monero Polyseed mnemonic encrypter class.
    It encrypts or decrypts polyseed data with a password (toggle operation).
    Calling Crypt twice with the same password returns the original data.
    """

    @staticmethod
    def Crypt(data: MoneroPolyseedDecodedData,
              password: str) -> MoneroPolyseedDecodedData:
        """
        Toggle encryption/decryption on the seed data.

        Args:
            data (MoneroPolyseedDecodedData): Decoded polyseed data
            password (str)                  : Password for encryption/decryption

        Returns:
            MoneroPolyseedDecodedData: Encrypted or decrypted polyseed data
        """
        # NFKD normalize password
        pass_norm = unicodedata.normalize("NFKD", password).encode("utf-8")

        # Derive 32-byte encryption mask
        mask = Pbkdf2HmacSha256.DeriveKey(
            password=pass_norm,
            salt=MoneroPolyseedMnemonicConst.KDF_MASK_SALT,
            itr_num=MoneroPolyseedMnemonicConst.KDF_NUM_ITERATIONS,
            dklen=MoneroPolyseedMnemonicConst.SECRET_BUFFER_SIZE,
        )

        # XOR secret with mask
        new_secret = bytearray(data.secret)
        for i in range(MoneroPolyseedMnemonicConst.SECRET_SIZE):
            new_secret[i] ^= mask[i]
        new_secret[MoneroPolyseedMnemonicConst.SECRET_SIZE - 1] &= MoneroPolyseedMnemonicConst.CLEAR_MASK

        # Toggle encrypted flag
        new_features = data.features ^ MoneroPolyseedMnemonicConst.ENCRYPTED_MASK

        # Recalculate checksum
        new_data = MoneroPolyseedDecodedData(
            secret=bytes(new_secret),
            birthday=data.birthday,
            features=new_features,
            checksum=0,
        )
        coeffs = MoneroPolyseedMnemonicUtils.DataToPoly(new_data)
        coeffs = MoneroPolyseedGf.PolyEncode(coeffs)
        new_data.checksum = coeffs[0]

        return new_data
