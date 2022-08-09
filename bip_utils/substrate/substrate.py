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

"""Module for Substrate keys computation and derivation."""

# Imports
from __future__ import annotations

from typing import Optional, Union

import sr25519

from bip_utils.ecc import IPrivateKey, IPublicKey
from bip_utils.substrate.conf import SubstrateCoinConf, SubstrateCoins, SubstrateConfGetter
from bip_utils.substrate.substrate_ex import SubstrateKeyError
from bip_utils.substrate.substrate_keys import SubstratePrivateKey, SubstratePublicKey
from bip_utils.substrate.substrate_path import SubstratePath, SubstratePathElem, SubstratePathParser


class SubstrateConst:
    """Class container for Substrate constants."""

    # Seed minimum length in bytes
    SEED_MIN_BYTE_LEN: int = 32


class Substrate:
    """
    Substrate class.
    It allows to compute Substrate keys and addresses.
    """

    m_priv_key: Optional[SubstratePrivateKey]
    m_pub_key: SubstratePublicKey
    m_path: SubstratePath
    m_coin_conf: SubstrateCoinConf

    #
    # Construction methods
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 coin_type: SubstrateCoins) -> Substrate:
        """
        Create a Substrate object from the specified seed.

        Args:
            seed_bytes (bytes)        : Seed bytes
            coin_type (SubstrateCoins): Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            ValueError: If the seed length is not valid
        """
        if len(seed_bytes) < SubstrateConst.SEED_MIN_BYTE_LEN:
            raise ValueError(
                f"Seed length is too small, it shall be at least {SubstrateConst.SEED_MIN_BYTE_LEN} bytes"
            )

        pub_key_bytes, priv_key_bytes = sr25519.pair_from_seed(  # pylint: disable=no-member
            seed_bytes[:SubstrateConst.SEED_MIN_BYTE_LEN]
        )
        return cls(priv_key=priv_key_bytes,
                   pub_key=pub_key_bytes,
                   path=SubstratePath(),
                   coin_conf=SubstrateConfGetter.GetConfig(coin_type))

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: Union[str, SubstratePath],
                        coin_type: SubstrateCoins) -> Substrate:
        """
        Create a Substrate object from the specified seed and path.

        Args:
            seed_bytes (bytes)                : Seed bytes
            path (str or SubstratePath object): Path
            coin_type (SubstrateCoins)        : Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            ValueError: If the seed length is not valid
            SubstratePathError: If the path is not valid
        """
        substrate_ctx = cls.FromSeed(seed_bytes, coin_type)
        return substrate_ctx.DerivePath(path)

    @classmethod
    def FromPrivateKey(cls,
                       priv_key: Union[bytes, IPrivateKey],
                       coin_type: SubstrateCoins) -> Substrate:
        """
        Create a Substrate object from the specified private key.

        Args:
            priv_key (bytes or IPrivateKey): Private key
            coin_type (SubstrateCoins)     : Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            SubstrateKeyError: If the key is not valid
        """
        return cls(priv_key=priv_key,
                   pub_key=None,
                   path=SubstratePath(),
                   coin_conf=SubstrateConfGetter.GetConfig(coin_type))

    @classmethod
    def FromPublicKey(cls,
                      pub_key: Union[bytes, IPublicKey],
                      coin_type: SubstrateCoins) -> Substrate:
        """
        Create a Substrate object from the specified public key.

        Args:
            pub_key (bytes or IPublicKey): Public key
            coin_type (SubstrateCoins)   : Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            SubstrateKeyError: If the key is not valid
        """
        if not isinstance(coin_type, SubstrateCoins):
            raise TypeError("Coin is not an enumerative of SubstrateCoins")

        return cls(priv_key=None,
                   pub_key=pub_key,
                   path=SubstratePath(),
                   coin_conf=SubstrateConfGetter.GetConfig(coin_type))

    #
    # Public methods
    #

    def __init__(self,
                 priv_key: Optional[Union[bytes, IPrivateKey]],
                 pub_key: Optional[Union[bytes, IPublicKey]],
                 path: SubstratePath,
                 coin_conf: SubstrateCoinConf) -> None:
        """
        Construct class.

        Args:
            priv_key (bytes or IPrivateKey)     : Private key, if None a public-only object will be created
            pub_key (bytes or IPublicKey)       : Public key
            path (SubstratePath object)         : Path
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If one of the key is not valid
        """

        # Private key object
        if priv_key is not None:
            self.m_priv_key = SubstratePrivateKey.FromBytesOrKeyObject(priv_key, coin_conf)
            # Use the provided public key if any. This is done because se25519 library returns both the
            # derived private and public keys, so we can avoid to compute the public key from the private key
            # that takes time
            self.m_pub_key = (SubstratePublicKey.FromBytesOrKeyObject(pub_key, coin_conf)
                              if pub_key is not None
                              else self.m_priv_key.PublicKey())
        # Public-only object
        else:
            assert isinstance(pub_key, (bytes, IPublicKey)), "Public key shall be specified for public-only objects"

            self.m_priv_key = None
            self.m_pub_key = SubstratePublicKey.FromBytesOrKeyObject(pub_key, coin_conf)

        self.m_path = path
        self.m_coin_conf = coin_conf

    def ChildKey(self,
                 path_elem: Union[str, SubstratePathElem]) -> Substrate:
        """
        Create and return a child key of the current one with the specified path element.

        Args:
            path_elem (str or SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstrateKeyError: If the index results in invalid keys
        """
        if isinstance(path_elem, str):
            path_elem = SubstratePathElem(path_elem)

        return self.__CkdPriv(path_elem) if not self.IsPublicOnly() else self.__CkdPub(path_elem)

    def DerivePath(self,
                   path: Union[str, SubstratePath]) -> Substrate:
        """
        Derive children keys from the specified path.

        Args:
            path (str or SubstratePath object): Path

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstratePathError: If the path is not valid
        """
        if isinstance(path, str):
            path = SubstratePathParser.Parse(path)

        substrate_obj = self
        # Derive children keys
        for path_elem in path:
            substrate_obj = substrate_obj.ChildKey(path_elem)

        return substrate_obj

    def ConvertToPublic(self) -> None:
        """Convert a private Substrate object into a public one."""
        self.m_priv_key = None

    def IsPublicOnly(self) -> bool:
        """
        Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_priv_key is None

    def CoinConf(self) -> SubstrateCoinConf:
        """
        Return coin configuration.

        Returns:
            SubstrateCoinConf object: SubstrateCoinConf object
        """
        return self.m_coin_conf

    def Path(self) -> SubstratePath:
        """
        Return path.

        Returns:
            SubstratePath object: SubstratePath object
        """
        return self.m_path

    def PrivateKey(self) -> SubstratePrivateKey:
        """
        Return private key object.

        Returns:
            SubstratePrivateKey object: SubstratePrivateKey object

        Raises:
            SubstrateKeyError: If internal key is public-only
        """
        if self.IsPublicOnly():
            raise SubstrateKeyError("Public-only deterministic keys have no private half")

        assert isinstance(self.m_priv_key, SubstratePrivateKey)
        return self.m_priv_key

    def PublicKey(self) -> SubstratePublicKey:
        """
        Return public key object.

        Returns:
            SubstratePublicKey object: SubstratePublicKey object
        """
        return self.m_pub_key

    #
    # Private methods
    #

    def __CkdPriv(self,
                  path_elem: SubstratePathElem) -> Substrate:
        """
        Create a child key of the specified path element using private derivation.

        Args:
            path_elem (SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object
        """
        assert isinstance(self.m_priv_key, SubstratePrivateKey)

        ex_key_pair = (path_elem.ChainCode(), self.m_pub_key.RawCompressed().ToBytes(), self.m_priv_key.Raw().ToBytes())

        if path_elem.IsHard():
            _, pub_key_bytes, priv_key_bytes = sr25519.hard_derive_keypair(ex_key_pair,  # pylint: disable=no-member
                                                                           b"")
        else:
            _, pub_key_bytes, priv_key_bytes = sr25519.derive_keypair(ex_key_pair,  # pylint: disable=no-member
                                                                      b"")

        return Substrate(priv_key=priv_key_bytes,
                         pub_key=pub_key_bytes,
                         path=self.m_path.AddElem(path_elem),
                         coin_conf=self.m_coin_conf)

    def __CkdPub(self,
                 path_elem: SubstratePathElem) -> Substrate:
        """
        Create a child key of the specified index using public derivation.

        Args:
            path_elem (SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstrateKeyError: If the path element is hard
        """
        if path_elem.IsHard():
            raise SubstrateKeyError("Public child derivation cannot be used to create a hardened child key")

        ex_key_pair = (path_elem.ChainCode(), self.m_pub_key.RawCompressed().ToBytes())

        _, pub_key_bytes = sr25519.derive_pubkey(ex_key_pair, b"")  # pylint: disable=no-member

        return Substrate(priv_key=None,
                         pub_key=pub_key_bytes,
                         path=self.m_path.AddElem(path_elem),
                         coin_conf=self.m_coin_conf)
