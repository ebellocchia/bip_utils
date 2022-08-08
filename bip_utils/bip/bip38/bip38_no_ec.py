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
from typing import Tuple, Union

from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip38.bip38_addr import Bip38Addr, Bip38PubKeyModes
from bip_utils.ecc import IPrivateKey, Secp256k1PrivateKey
from bip_utils.utils.crypto import AesEcbDecrypter, AesEcbEncrypter, Scrypt
from bip_utils.utils.misc import BytesUtils, IntegerUtils, StringUtils


class Bip38NoEcConst:
    """Class container for BIP38 no EC constants."""

    # Encrypted key byte length
    ENC_KEY_BYTE_LEN: int = 39
    # Encrypted key prefix
    ENC_KEY_PREFIX: bytes = b"\x01\x42"
    # Flagbyte for compressed public key
    FLAGBYTE_COMPRESSED: bytes = b"\xe0"
    # Flagbyte for uncompressed public key
    FLAGBYTE_UNCOMPRESSED: bytes = b"\xc0"
    # Parameters for scrypt algorithm
    SCRYPT_KEY_LEN: int = 64
    SCRYPT_N: int = 16384
    SCRYPT_P: int = 8
    SCRYPT_R: int = 8


class _Bip38NoEcUtils:
    """Class container for BIP38 no EC utility functions."""

    @staticmethod
    def AddressHash(priv_key_bytes: bytes,
                    pub_key_mode: Bip38PubKeyModes) -> bytes:
        """
        Compute the address hash as specified in BIP38 (without EC multiplication).

        Args:
            priv_key_bytes (bytes)         : private key bytes
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            bytes: Address hash

        Raises:
            ValueError: If the private key is not valid
        """
        return Bip38Addr.AddressHash(Secp256k1PrivateKey.FromBytes(priv_key_bytes).PublicKey(),
                                     pub_key_mode)

    @staticmethod
    def DeriveKeyHalves(passphrase: str,
                        address_hash: bytes) -> Tuple[bytes, bytes]:
        """
        Compute the scrypt as specified in BIP38 (without EC multiplication) and derive the two key halves.

        Args:
            passphrase (str)    : Passphrase
            address_hash (bytes): Address hash

        Returns:
            tuple[bytes, bytes]: Derived key halves
        """

        # Derive a key from passphrase and address hash
        key = Scrypt.DeriveKey(StringUtils.NormalizeNfc(passphrase),
                               address_hash,
                               key_len=Bip38NoEcConst.SCRYPT_KEY_LEN,
                               n=Bip38NoEcConst.SCRYPT_N,
                               r=Bip38NoEcConst.SCRYPT_R,
                               p=Bip38NoEcConst.SCRYPT_P)
        # Split the resulting 64 bytes in half
        derived_half_1 = key[:Bip38NoEcConst.SCRYPT_KEY_LEN // 2]
        derived_half_2 = key[Bip38NoEcConst.SCRYPT_KEY_LEN // 2:]

        return derived_half_1, derived_half_2


class Bip38NoEcEncrypter:
    """
    BIP38 encrypter class.
    It encrypts a private key using the algorithm specified in BIP38 without EC multiplication.
    """

    @staticmethod
    def Encrypt(priv_key: Union[bytes, IPrivateKey],
                passphrase: str,
                pub_key_mode: Bip38PubKeyModes) -> str:
        """
        Encrypt the specified private key.

        Args:
            priv_key (bytes or IPrivateKey): Private key bytes or object
            passphrase (str)               : Passphrase
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            str: Encrypted private key

        Raises:
            TypeError: If the private key is not a Secp256k1PrivateKey
            ValueError: If the private key bytes are not valid
        """

        # Convert to private key to check if bytes are valid
        if isinstance(priv_key, bytes):
            priv_key = Secp256k1PrivateKey.FromBytes(priv_key)
        elif not isinstance(priv_key, Secp256k1PrivateKey):
            raise TypeError("A secp256k1 private key is required")

        # Compute address hash
        priv_key_bytes = priv_key.Raw().ToBytes()
        address_hash = _Bip38NoEcUtils.AddressHash(priv_key_bytes, pub_key_mode)

        # Derive key halves from the passphrase and address hash
        derived_half_1, derived_half_2 = _Bip38NoEcUtils.DeriveKeyHalves(passphrase, address_hash)
        # Encrypt private key in two halves
        encrypted_half_1, encrypted_half_2 = Bip38NoEcEncrypter.__EncryptPrivateKey(priv_key_bytes,
                                                                                    derived_half_1,
                                                                                    derived_half_2)

        # Get flagbyte
        flagbyte = (Bip38NoEcConst.FLAGBYTE_COMPRESSED
                    if pub_key_mode == Bip38PubKeyModes.COMPRESSED
                    else Bip38NoEcConst.FLAGBYTE_UNCOMPRESSED)

        # Concatenate all parts
        enc_key_bytes = Bip38NoEcConst.ENC_KEY_PREFIX + flagbyte + address_hash + encrypted_half_1 + encrypted_half_2

        # Encode in Base58Check
        return Base58Encoder.CheckEncode(enc_key_bytes)

    @staticmethod
    def __EncryptPrivateKey(priv_key_bytes: bytes,
                            derived_half_1: bytes,
                            derived_half_2: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt private key in two halves.

        Args:
            priv_key_bytes (bytes): Private key
            derived_half_1 (bytes): First half of derived key
            derived_half_2 (bytes): Second half of derived key

        Returns:
            tuple[bytes, bytes]: Two encrypted halves
        """

        # Use derived_half_2 as AES key
        aes_enc = AesEcbEncrypter(derived_half_2)
        aes_enc.AutoPad(False)

        # Encrypt the first half: priv_key[0...15] xor derived_half_1[0...15]
        encrypted_half_1 = aes_enc.Encrypt(BytesUtils.Xor(priv_key_bytes[:16], derived_half_1[:16]))
        # Encrypt the second half: priv_key[16...31] xor derived_half_1[16...31]
        encrypted_half_2 = aes_enc.Encrypt(BytesUtils.Xor(priv_key_bytes[16:], derived_half_1[16:]))

        return encrypted_half_1, encrypted_half_2


class Bip38NoEcDecrypter:
    """
    BIP38 decrypter class.
    It decrypts a private key using the algorithm specified in BIP38 without EC multiplication.
    """

    @staticmethod
    def Decrypt(priv_key_enc: str,
                passphrase: str) -> Tuple[bytes, Bip38PubKeyModes]:
        """
        Decrypt the specified private key.

        Args:
            priv_key_enc (str): Encrypted private key bytes
            passphrase (str)  : Passphrase

        Returns:
            tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the encrypted key is not valid
        """

        # Decode private key
        priv_key_enc_bytes = Base58Decoder.CheckDecode(priv_key_enc)
        # Check length
        if len(priv_key_enc_bytes) != Bip38NoEcConst.ENC_KEY_BYTE_LEN:
            raise ValueError(f"Invalid encrypted key length ({len(priv_key_enc_bytes)})")

        # Get all the parts back
        prefix = priv_key_enc_bytes[:2]
        flagbyte = IntegerUtils.ToBytes(priv_key_enc_bytes[2])
        address_hash = priv_key_enc_bytes[3:7]
        encrypted_half_1 = priv_key_enc_bytes[7:23]
        encrypted_half_2 = priv_key_enc_bytes[23:]

        # Check prefix and flagbyte
        if prefix != Bip38NoEcConst.ENC_KEY_PREFIX:
            raise ValueError(f"Invalid prefix ({BytesUtils.ToHexString(prefix)})")
        if flagbyte not in (Bip38NoEcConst.FLAGBYTE_COMPRESSED, Bip38NoEcConst.FLAGBYTE_UNCOMPRESSED):
            raise ValueError(f"Invalid flagbyte ({BytesUtils.ToHexString(flagbyte)})")

        # Derive key halves from the passphrase and address hash
        derived_half_1, derived_half_2 = _Bip38NoEcUtils.DeriveKeyHalves(passphrase, address_hash)
        # Get the private key back by decrypting
        priv_key_bytes = Bip38NoEcDecrypter.__DecryptAndGetPrivKey(encrypted_half_1,
                                                                   encrypted_half_2,
                                                                   derived_half_1,
                                                                   derived_half_2)

        # Get public key mode
        pub_key_mode = (Bip38PubKeyModes.COMPRESSED
                        if flagbyte == Bip38NoEcConst.FLAGBYTE_COMPRESSED
                        else Bip38PubKeyModes.UNCOMPRESSED)

        # Verify the address hash
        address_hash_got = _Bip38NoEcUtils.AddressHash(priv_key_bytes, pub_key_mode)
        if address_hash != address_hash_got:
            raise ValueError(
                f"Invalid address hash (expected: {BytesUtils.ToHexString(address_hash)}, "
                f"got: {BytesUtils.ToHexString(address_hash_got)})"
            )

        return priv_key_bytes, pub_key_mode

    @staticmethod
    def __DecryptAndGetPrivKey(encrypted_half_1: bytes,
                               encrypted_half_2: bytes,
                               derived_half_1: bytes,
                               derived_half_2: bytes) -> bytes:
        """
        Decrypt and get back private key.

        Args:
            encrypted_half_1 (bytes): First encrypted half
            encrypted_half_2 (bytes): Second encrypted half
            derived_half_1 (bytes)  : First half of derived key
            derived_half_2 (bytes)  : Second half of derived key

        Returns:
            bytes: Decrypted private key
        """

        # Use derived_half_2 as AES key
        aes_dec = AesEcbDecrypter(derived_half_2)
        aes_dec.AutoUnPad(False)

        # Decrypt using AES256Decrypt
        decrypted_half_1 = aes_dec.Decrypt(encrypted_half_1)
        decrypted_half_2 = aes_dec.Decrypt(encrypted_half_2)

        # Get the private key back by XORing bytes
        return BytesUtils.Xor(decrypted_half_1 + decrypted_half_2, derived_half_1)
