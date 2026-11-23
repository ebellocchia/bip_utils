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
Module for SLIP39 master secret encryption.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from typing import Iterable, Tuple

from bip_utils.utils.crypto import Pbkdf2HmacSha256
from bip_utils.utils.misc import BytesUtils, IntegerUtils


class Slip39MasterSecretEncrypterConst:
    """Class container for SLIP39 master secret encrypter constants."""

    # Number of Feistel rounds
    ROUNDS_NUM: int = 4
    # Base number of PBKDF2 iterations (for all rounds)
    BASE_ITR_NUM: int = 10000
    # Salt prefix (only when the extendable backup flag is not set)
    SALT_PREFIX: bytes = b"shamir"
    # Identifier length in bytes inside the salt
    SALT_ID_BYTE_LEN: int = 2
    # Allowed passphrase characters (printable ASCII)
    PASSPHRASE_MIN_CHAR: int = 32
    PASSPHRASE_MAX_CHAR: int = 126


class Slip39MasterSecretEncrypter:
    """
    SLIP39 master secret encrypter class.
    It encrypts/decrypts the master secret with a passphrase, using a 4-round Feistel network with PBKDF2 as round
    function.
    """

    @classmethod
    def Encrypt(cls,
                master_secret: bytes,
                passphrase: str,
                iteration_exponent: int,
                identifier: int,
                extendable: bool) -> bytes:
        """
        Encrypt the master secret.

        Args:
            master_secret (bytes)   : Master secret
            passphrase (str)        : Passphrase
            iteration_exponent (int): Iteration exponent
            identifier (int)        : Identifier
            extendable (bool)       : Extendable backup flag

        Returns:
            bytes: Encrypted master secret

        Raises:
            ValueError: If the passphrase is not valid
        """
        return cls.__Feistel(master_secret,
                             range(Slip39MasterSecretEncrypterConst.ROUNDS_NUM),
                             *cls.__RoundParams(passphrase, iteration_exponent, identifier, extendable))

    @classmethod
    def Decrypt(cls,
                enc_master_secret: bytes,
                passphrase: str,
                iteration_exponent: int,
                identifier: int,
                extendable: bool) -> bytes:
        """
        Decrypt the master secret.

        Args:
            enc_master_secret (bytes): Encrypted master secret
            passphrase (str)         : Passphrase
            iteration_exponent (int) : Iteration exponent
            identifier (int)         : Identifier
            extendable (bool)        : Extendable backup flag

        Returns:
            bytes: Master secret

        Raises:
            ValueError: If the passphrase is not valid
        """
        return cls.__Feistel(enc_master_secret,
                             reversed(range(Slip39MasterSecretEncrypterConst.ROUNDS_NUM)),
                             *cls.__RoundParams(passphrase, iteration_exponent, identifier, extendable))

    @staticmethod
    def __RoundParams(passphrase: str,
                      iteration_exponent: int,
                      identifier: int,
                      extendable: bool) -> Tuple[bytes, bytes, int]:
        """
        Get the parameters of the round function.

        Args:
            passphrase (str)        : Passphrase
            iteration_exponent (int): Iteration exponent
            identifier (int)        : Identifier
            extendable (bool)       : Extendable backup flag

        Returns:
            tuple[bytes, bytes, int]: Passphrase bytes (index 0), salt prefix (index 1), iterations per round (index 2)

        Raises:
            ValueError: If the passphrase is not valid
        """
        if any(not (Slip39MasterSecretEncrypterConst.PASSPHRASE_MIN_CHAR
                    <= ord(c)
                    <= Slip39MasterSecretEncrypterConst.PASSPHRASE_MAX_CHAR) for c in passphrase):
            raise ValueError("The passphrase shall only contain printable ASCII characters")

        # The identifier is part of the salt only if the extendable backup flag is not set
        salt = (b""
                if extendable
                else Slip39MasterSecretEncrypterConst.SALT_PREFIX + IntegerUtils.ToBytes(
                    identifier, bytes_num=Slip39MasterSecretEncrypterConst.SALT_ID_BYTE_LEN
                ))
        itr_num = ((Slip39MasterSecretEncrypterConst.BASE_ITR_NUM << iteration_exponent)
                   // Slip39MasterSecretEncrypterConst.ROUNDS_NUM)
        return passphrase.encode("ascii"), salt, itr_num

    @staticmethod
    def __Feistel(data: bytes,
                  rounds: Iterable[int],
                  passphrase_bytes: bytes,
                  salt: bytes,
                  itr_num: int) -> bytes:
        """
        Apply the Feistel network (encryption and decryption only differ in the rounds order).

        Args:
            data (bytes)            : Data
            rounds (iterable[int])  : Rounds order
            passphrase_bytes (bytes): Passphrase bytes
            salt (bytes)            : Salt prefix
            itr_num (int)           : PBKDF2 iterations per round

        Returns:
            bytes: Processed data
        """
        half_len = len(data) // 2
        left, right = data[:half_len], data[half_len:]
        for i in rounds:
            round_key = Pbkdf2HmacSha256.DeriveKey(bytes([i]) + passphrase_bytes, salt + right, itr_num, len(right))
            left, right = right, BytesUtils.Xor(left, round_key)
        return right + left
