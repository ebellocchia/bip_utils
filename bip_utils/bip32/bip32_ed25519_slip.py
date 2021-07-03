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


# Imports
from typing import Union
from bip_utils.bip32.bip32_base import Bip32Base
from bip_utils.bip32.bip32_ed25519_slip_base import Bip32Ed25519SlipBaseConst, Bip32Ed25519SlipBase
from bip_utils.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.bip32.bip32_path import Bip32Path
from bip_utils.conf import Bip44BitcoinMainNet, KeyNetVersions
from bip_utils.ecc import EllipticCurveTypes


class Bip32Ed25519SlipConst:
    """ Class container for BIP32 ed25519 constants. """

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.ED25519


class Bip32Ed25519Slip(Bip32Ed25519SlipBase):
    """ BIP32 ed25519 class. It allows master key generation and children keys derivation using ed25519 curve.
    Derivation based on SLIP-0010.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: KeyNetVersions = Bip44BitcoinMainNet.KeyNetVersions()) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                           : Seed bytes
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeed(seed_bytes,
                             Bip32Ed25519SlipBaseConst.MASTER_KEY_HMAC_KEY,
                             key_net_ver,
                             Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: Union[str, Bip32Path],
                        key_net_ver: KeyNetVersions = Bip44BitcoinMainNet.KeyNetVersions()) -> Bip32Base:
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                           : Seed bytes
            path (str or Bip32Path object)               : Path
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            ValueError: If the seed length is too short
            Bip32PathError: If the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls._FromSeedAndPath(seed_bytes,
                                    Bip32Ed25519SlipBaseConst.MASTER_KEY_HMAC_KEY,
                                    path,
                                    key_net_ver,
                                    Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        key_net_ver: KeyNetVersions = Bip44BitcoinMainNet.KeyNetVersions()) -> Bip32Base:
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                                : Extended key string
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls._FromExtendedKey(key_str,
                                    key_net_ver,
                                    Bip32Ed25519SlipConst.CURVE_TYPE)

    @classmethod
    def FromPrivateKey(cls,
                       key_bytes: bytes,
                       key_net_ver: KeyNetVersions = Bip44BitcoinMainNet.KeyNetVersions()) -> Bip32Base:
        """ Create a Bip32 object from the specified private key.
        The key will be considered a master key with the chain code set to zero,
        since there is no way to recover the key derivation data.

        Args:
            key_bytes (bytes)                            : Key bytes
            key_net_ver (KeyNetVersions object, optional): KeyNetVersions object (Bip32 main net version by default)

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the key is not valid
        """
        return cls._FromPrivateKey(key_bytes,
                                   key_net_ver,
                                   Bip32Ed25519SlipConst.CURVE_TYPE)

    #
    # Protected methods
    #

    def _CkdPriv(self,
                 index: Bip32KeyIndex) -> Bip32Base:
        """ Create a child key of the specified index using private derivation.
        It shall be implemented by children classes depending on the elliptic curve.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        return self._CkdPrivEd25519Slip(self, index)
