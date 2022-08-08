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

"""Module for Substrate paths parsing and handling."""

# Imports
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, Iterator, List, Optional, Sequence, Type, Union

from bip_utils.substrate.scale import (
    SubstrateScaleBytesEncoder, SubstrateScaleEncoderBase, SubstrateScaleU8Encoder, SubstrateScaleU16Encoder,
    SubstrateScaleU32Encoder, SubstrateScaleU64Encoder, SubstrateScaleU128Encoder, SubstrateScaleU256Encoder
)
from bip_utils.substrate.substrate_ex import SubstratePathError
from bip_utils.utils.crypto import Blake2b256


class SubstratePathConst:
    """Container for Substrate path constants."""

    # Encoded element maximum length in bytes
    ENCODED_ELEM_MAX_BYTE_LEN: int = 32
    # Regex for path
    RE_PATH: str = r"\/+[^/]+"

    # Soft path prefix
    SOFT_PATH_PREFIX: str = "/"
    # hard path prefix
    HARD_PATH_PREFIX: str = "//"

    # SCALE encoders for integers
    SCALE_INT_ENCODERS: Dict[int, Type[SubstrateScaleEncoderBase]] = {
        8: SubstrateScaleU8Encoder,
        16: SubstrateScaleU16Encoder,
        32: SubstrateScaleU32Encoder,
        64: SubstrateScaleU64Encoder,
        128: SubstrateScaleU128Encoder,
        256: SubstrateScaleU256Encoder,
    }


class SubstratePathElem:
    """
    Substrate path element.
    It represents a Substrate path element.
    """

    m_elem: str
    m_is_hard: bool

    def __init__(self,
                 elem: str) -> None:
        """
        Construct class.

        Args:
            elem (str): Path element

        Raises:
            SubstratePathError: If the path element is not valid
        """
        if not self.__IsElemValid(elem):
            raise SubstratePathError(f"Invalid path element ({elem})")

        self.m_elem = elem.replace("/", "")
        self.m_is_hard = elem.startswith(SubstratePathConst.HARD_PATH_PREFIX)

    def IsHard(self) -> bool:
        """
        Get if the element is hard.

        Returns:
            bool: True if hard, false otherwise
        """
        return self.m_is_hard

    def IsSoft(self) -> bool:
        """
        Get if the element is soft.

        Returns:
            bool: True if soft, false otherwise
        """
        return not self.IsHard()

    @lru_cache()
    def ChainCode(self) -> bytes:
        """
        Return the chain code.

        Returns:
            bytes: Chain code
        """
        return self.__ComputeChainCode()

    def ToStr(self) -> str:
        """
        Get the path element as a string.

        Returns:
            str: Path element as a string
        """
        prefix = SubstratePathConst.HARD_PATH_PREFIX if self.m_is_hard else SubstratePathConst.SOFT_PATH_PREFIX
        return prefix + self.m_elem

    def __str__(self) -> str:
        """
        Get the path element as a string.

        Returns:
            str: Path element as a string
        """
        return self.ToStr()

    def __ComputeChainCode(self) -> bytes:
        """
        Compute chain code.

        Returns:
            bytes: Chain code

        Raises:
            SubstratePathError: If path is a number bigger than 256-bit
        """

        # Integer
        if self.m_elem.isnumeric():
            bit_len = int(self.m_elem).bit_length()

            # Find the correct scale encoder
            scale_enc = None
            for min_bit_len, int_scale_enc in SubstratePathConst.SCALE_INT_ENCODERS.items():
                if bit_len <= min_bit_len:
                    scale_enc = int_scale_enc
                    break

            if scale_enc is None:
                raise SubstratePathError(f"Invalid integer bit length ({bit_len})")
        # String
        else:
            scale_enc = SubstrateScaleBytesEncoder

        # Encode element
        enc_data = scale_enc.Encode(self.m_elem)

        # Compute chain code
        max_len = SubstratePathConst.ENCODED_ELEM_MAX_BYTE_LEN
        if len(enc_data) > max_len:
            chain_code = Blake2b256.QuickDigest(enc_data)
        else:
            chain_code = enc_data.ljust(max_len, b"\x00")

        return chain_code

    @staticmethod
    def __IsElemValid(elem: str) -> bool:
        """
        Get a path element is valid.

        Args:
            elem (str): Path element

        Returns:
            bool: True if valid, false otherwise
        """
        return ((elem.startswith(SubstratePathConst.SOFT_PATH_PREFIX)
                 or elem.startswith(SubstratePathConst.HARD_PATH_PREFIX))
                and elem.rfind("/") < 2
                and len(elem.replace("/", "")) > 0)


class SubstratePath:
    """
    Substrate path.
    It represents a Substrate path.
    """

    m_elems: List[SubstratePathElem]

    def __init__(self,
                 elems: Optional[Sequence[Union[str, SubstratePathElem]]] = None) -> None:
        """
        Construct class.

        Args:
            elems (list, optional): Path elements (default: empty)

        Raises:
            SubstratePathError: If the path element is not valid
        """
        self.m_elems = ([]
                        if elems is None
                        else [SubstratePathElem(elem) if isinstance(elem, str) else elem for elem in elems])

    def AddElem(self,
                elem: Union[str, SubstratePathElem]) -> SubstratePath:
        """
        Return a new path object with the specified element added.

        Args:
            elem (str or SubstratePathElem): Path element

        Returns:
            SubstratePath object: SubstratePath object

        Raises:
            SubstratePathError: If the path element is not valid
        """
        if isinstance(elem, str):
            elem = SubstratePathElem(elem)
        return SubstratePath(self.m_elems + [elem])

    def Length(self) -> int:
        """
        Get the number of elements of the path.

        Returns:
            int: Number of elements
        """
        return len(self.m_elems)

    def ToList(self) -> List[str]:
        """
        Get the path as a list of strings.

        Returns:
            list[str]: Path as a list of strings
        """
        return [str(elem) for elem in self.m_elems]

    def ToStr(self) -> str:
        """
        Get the path as a string.

        Returns:
            str: Path as a string
        """
        return "".join(self.ToList())

    def __str__(self) -> str:
        """
        Get the path as a string.

        Returns:
            str: Path as a list of integers
        """
        return self.ToStr()

    def __getitem__(self,
                    idx: int) -> SubstratePathElem:
        """
        Get the specified element index.

        Args:
            idx (int): Element index

        Returns:
            SubstratePathElem object: SubstratePathElem object
        """
        return self.m_elems[idx]

    def __iter__(self) -> Iterator[SubstratePathElem]:
        """
        Get the iterator to the current element.

        Returns:
            Iterator object: Iterator to the current element
        """
        yield from self.m_elems


class SubstratePathParser:
    """
    Substrate path parser.
    It parses a Substrate path and returns a SubstratePath object.
    """

    @staticmethod
    def Parse(path: str) -> SubstratePath:
        """
        Parse a path and return a SubstratePath object.

        Args:
            path (str): Path

        Returns:
            SubstratePath object: SubstratePath object

        Raises:
            SubstratePathError: If the path element is not valid
        """
        if len(path) > 0 and not path.startswith("/"):
            raise SubstratePathError(f"Invalid path ({path})")

        paths = re.findall(SubstratePathConst.RE_PATH, path)
        return SubstratePath(list(paths))
