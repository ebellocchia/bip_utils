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
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki.
"""

# Imports
from typing import Union
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip44 import Bip44
from bip_utils.bip.conf.bip44 import Bip44Coins
from bip_utils.ecc import IPrivateKey, Secp256k1PrivateKey
from bip_utils.utils.misc import AesEcbDecrypter, AesEcbEncrypter, ConvUtils, CryptoUtils


class Bip38NoEcConst:
    """Class container for BIP38 constants."""

    # Encrypted length for not EC multiplication
    ENC_LEN: int = 39
    # Prefix for not EC multiplication
    ENC_PREFIX: bytes = b"\x01\x42"
    # Flag byte for compressed public key
    COMPRESSED_FLAGBYTE: bytes = b"\xe0"
    # Address hash length
    ADDR_HASH_LEN: int = 4
    # Parameters for scrypt algorithm
    SCRYPT_KEY_LEN: int = 64
    SCRYPT_N: int = 16384
    SCRYPT_P: int = 8
    SCRYPT_R: int = 8


class Bip38NoEcUtils:
    """Class container for BIP38 utility functions."""

    @staticmethod
    def AddressHash(priv_key_bytes: bytes) -> bytes:
        """
        Compute the address hash as specified in BIP38 (without EC multiplication).

        Args:
            priv_key_bytes (bytes): private key bytes

        Returns:
            bytes: Address hash
        """

        # Compute the Bitcoin address (ASCII)
        address = Bip44.FromPrivateKey(priv_key_bytes, Bip44Coins.BITCOIN).PublicKey().ToAddress()
        # Take the first four bytes of SHA256(SHA256())
        return CryptoUtils.DoubleSha256(address)[:Bip38NoEcConst.ADDR_HASH_LEN]

    @staticmethod
    def Scrypt(passphrase: str,
               address_hash: bytes) -> bytes:
        """
        Compute the scrypt as specified in BIP38 (without EC multiplication).

        Args:
            passphrase (str)  : Passphrase
            address_hash (str): Address hash

        Returns:
            bytes: Derived key
        """
        return CryptoUtils.Scrypt(ConvUtils.NormalizeNfc(passphrase),
                                  address_hash,
                                  key_len=Bip38NoEcConst.SCRYPT_KEY_LEN,
                                  n=Bip38NoEcConst.SCRYPT_N,
                                  r=Bip38NoEcConst.SCRYPT_R,
                                  p=Bip38NoEcConst.SCRYPT_P)


class Bip38NoEcEncrypter:
    """
    BIP38 encrypter class.
    It encrypts a private key using the algorithm specified in BIP38 without EC multiplication.
    """

    @staticmethod
    def Encrypt(priv_key: Union[bytes, IPrivateKey],
                passphrase: str) -> str:
        """
        Encrypt the specified private key.

        Args:
            priv_key (bytes or IPrivateKey): Private key bytes or object
            passphrase (str)               : Passphrase

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
        address_hash = Bip38NoEcUtils.AddressHash(priv_key_bytes)

        # Derive a key from the passphrase using scrypt
        key = Bip38NoEcUtils.Scrypt(passphrase, address_hash)
        # Split the resulting 64 bytes in half
        derived_half_1 = key[:Bip38NoEcConst.SCRYPT_KEY_LEN // 2]
        derived_half_2 = key[Bip38NoEcConst.SCRYPT_KEY_LEN // 2:]

        # Use derived_half_2 as AES key
        aes_enc = AesEcbEncrypter(derived_half_2)
        aes_enc.AutoPad(False)

        # Do AES256Encrypt(block = bitcoinprivkey[0...15] xor derivedhalf1[0...15], key = derivedhalf2)
        encrypted_half_1 = aes_enc.Encrypt(ConvUtils.XorBytes(priv_key_bytes[:16], derived_half_1[:16]))
        # Do AES256Encrypt(block = bitcoinprivkey[16...31] xor derivedhalf1[16...31], key = derivedhalf2)
        encrypted_half_2 = aes_enc.Encrypt(ConvUtils.XorBytes(priv_key_bytes[16:], derived_half_1[16:]))

        # Concatenate all parts
        enc_key_bytes = (Bip38NoEcConst.ENC_PREFIX + Bip38NoEcConst.COMPRESSED_FLAGBYTE + address_hash
                         + encrypted_half_1 + encrypted_half_2)

        # Encode in Base58Check
        return Base58Encoder.CheckEncode(enc_key_bytes)


class Bip38NoEcDecrypter:
    """
    BIP38 decrypter class.
    It decrypts a private key using the algorithm specified in BIP38 without EC multiplication.
    """

    @staticmethod
    def Decrypt(priv_key_enc: str,
                passphrase: str) -> bytes:
        """
        Decrypt the specified private key.

        Args:
            priv_key_enc (str): Encrypted private key bytes
            passphrase (str)  : Passphrase

        Returns:
            bytes: Decrypted private key

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the encrypted key is not valid
        """

        # Decode private key
        priv_key_enc_bytes = Base58Decoder.CheckDecode(priv_key_enc)
        # Check encrypted length
        if len(priv_key_enc_bytes) != Bip38NoEcConst.ENC_LEN:
            raise ValueError(f"Invalid encrypted length ({len(priv_key_enc_bytes)})")

        # Get all the parts back
        prefix = priv_key_enc_bytes[:2]
        flagbyte = ConvUtils.IntegerToBytes(priv_key_enc_bytes[2])
        address_hash = priv_key_enc_bytes[3:7]
        encrypted_half_1 = priv_key_enc_bytes[7:23]
        encrypted_half_2 = priv_key_enc_bytes[23:]

        # Check prefix and flagbyte
        if prefix != Bip38NoEcConst.ENC_PREFIX:
            raise ValueError(f"Invalid prefix ({ConvUtils.BytesToHexString(prefix)})")
        if flagbyte != Bip38NoEcConst.COMPRESSED_FLAGBYTE:
            raise ValueError(f"Invalid flagbyte ({ConvUtils.BytesToHexString(flagbyte)})")

        # Derive the two halves by passing the passphrase and addresshash into scrypt function
        key = Bip38NoEcUtils.Scrypt(passphrase, address_hash)
        derived_half_1 = key[:Bip38NoEcConst.SCRYPT_KEY_LEN // 2]
        derived_half_2 = key[Bip38NoEcConst.SCRYPT_KEY_LEN // 2:]

        # Use derived_half_2 as AES key
        aes_dec = AesEcbDecrypter(derived_half_2)
        aes_dec.AutoUnPad(False)

        # Decrypt using AES256Decrypt
        decrypted_half_1 = aes_dec.Decrypt(encrypted_half_1)
        decrypted_half_2 = aes_dec.Decrypt(encrypted_half_2)
        # Get the private key back by XORing bytes
        priv_key_bytes = ConvUtils.XorBytes(decrypted_half_1 + decrypted_half_2, derived_half_1)

        # Check private key
        if not Secp256k1PrivateKey.IsValidBytes(priv_key_bytes):
            raise ValueError(f"Invalid decrypted key ({ConvUtils.BytesToHexString(priv_key_bytes)})")

        # Check the address hash
        got_address_hash = Bip38NoEcUtils.AddressHash(priv_key_bytes)
        if address_hash != got_address_hash:
            raise ValueError(
                f"Invalid address hash(expected: {ConvUtils.BytesToHexString(address_hash)}, "
                f"got: {ConvUtils.BytesToHexString(got_address_hash)}"
            )

        return priv_key_bytes
