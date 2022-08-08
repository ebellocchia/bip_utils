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

"""
Module for BIP38 encryption/decryption.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
"""

# Imports
from typing import Optional, Tuple, Union

from bip_utils.bip.bip38.bip38_addr import Bip38PubKeyModes
from bip_utils.bip.bip38.bip38_ec import Bip38EcDecrypter, Bip38EcKeysGenerator
from bip_utils.bip.bip38.bip38_no_ec import Bip38NoEcDecrypter, Bip38NoEcEncrypter
from bip_utils.ecc import IPrivateKey


class Bip38Encrypter:
    """
    BIP38 encrypter class.
    It encrypts a private key using the algorithm specified in BIP38.
    """

    @staticmethod
    def EncryptNoEc(priv_key: Union[bytes, IPrivateKey],
                    passphrase: str,
                    pub_key_mode: Bip38PubKeyModes = Bip38PubKeyModes.COMPRESSED) -> str:
        """
        Encrypt the specified private key without EC multiplication.

        Args:
            priv_key (bytes or IPrivateKey)          : Private key bytes or object
            passphrase (str)                         : Passphrase
            pub_key_mode (Bip38PubKeyModes, optional): Public key mode

        Returns:
            str: Encrypted private key

        Raises:
            TypeError: If the private key is not a Secp256k1PrivateKey
            ValueError: If the private key bytes are not valid
        """
        return Bip38NoEcEncrypter.Encrypt(priv_key, passphrase, pub_key_mode)

    @staticmethod
    def GeneratePrivateKeyEc(passphrase: str,
                             pub_key_mode: Bip38PubKeyModes = Bip38PubKeyModes.COMPRESSED,
                             lot_num: Optional[int] = None,
                             sequence_num: Optional[int] = None) -> str:
        """
        Generate a random encrypted private key with EC multiplication, using the specified parameters.
        This will generate the intermediate passphrase and use it immediately for generating the private key.

        Args:
            passphrase (str)                         : Passphrase
            pub_key_mode (Bip38PubKeyModes, optional): Public key mode
            lot_num (int, optional)                  : Lot number
            sequence_num (int, optional)             : Sequence number

        Returns:
            str: Encrypted private key
        """
        int_pass = Bip38EcKeysGenerator.GenerateIntermediatePassphrase(passphrase,
                                                                       lot_num,
                                                                       sequence_num)
        return Bip38EcKeysGenerator.GeneratePrivateKey(int_pass, pub_key_mode)


class Bip38Decrypter:
    """
    BIP38 decrypter class.
    It decrypts a private key using the algorithm specified in BIP38.
    """

    @staticmethod
    def DecryptNoEc(priv_key_enc: str,
                    passphrase: str) -> Tuple[bytes, Bip38PubKeyModes]:
        """
        Decrypt the specified private key without EC multiplication.

        Args:
            priv_key_enc (str): Encrypted private key bytes
            passphrase (str)  : Passphrase

        Returns:
            tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the encrypted key is not valid
        """
        return Bip38NoEcDecrypter.Decrypt(priv_key_enc, passphrase)

    @staticmethod
    def DecryptEc(priv_key_enc: str,
                  passphrase: str) -> Tuple[bytes, Bip38PubKeyModes]:
        """
        Decrypt the specified private key with EC multiplication.

        Args:
            priv_key_enc (str): Encrypted private key bytes
            passphrase (str)  : Passphrase

        Returns:
            tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the encrypted key is not valid
        """
        return Bip38EcDecrypter.Decrypt(priv_key_enc, passphrase)
