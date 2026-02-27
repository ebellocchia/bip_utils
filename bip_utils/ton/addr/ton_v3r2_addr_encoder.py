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
Module containing utility classes for TON V3R2 address computation.

Reference: https://github.com/ton-org/ton/blob/main/src/wallets/v3/r2.ts
"""

# Imports
from pytoniq_core import Address, Cell, begin_cell

from bip_utils.ton.ton_keys import TonPublicKey
from bip_utils.utils.misc import Base64Decoder


class TonV3R2AddrEncoderConst:
    """Class container for Ton V3R2 address encoder constants."""

    CONTRACT_CODE: bytes = Base64Decoder.Decode("te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0=") # noqa: E501
    WORKCHAIN: int = 0


class TonV3R2AddrEncoder:
    """TON V3R2 address encoder class."""

    m_pub_key: bytes

    def __init__(self,
                 pub_key_obj: TonPublicKey):
        """
        Construct class.

        Args:
            pub_key_obj (TonPublicKey object): Public key object
        """
        self.m_pub_key = pub_key_obj.RawCompressed().ToBytes()[1:]

    def Encode(self,
               is_bounceable: bool) -> str:
        """
        Encode public key to V3R2 address.

        Args:
            is_bounceable (bool): Whether the address is bounceable

        Returns:
            str: Address string
        """
        wallet_id = 698983191 + TonV3R2AddrEncoderConst.WORKCHAIN

        code = Cell.one_from_boc(TonV3R2AddrEncoderConst.CONTRACT_CODE)

        data = (begin_cell().store_uint(0, 32)
                            .store_uint(wallet_id, 32)
                            .store_bytes(self.m_pub_key)
                            .end_cell())

        hash = (begin_cell().store_bit(False)
                            .store_bit(False)
                            .store_maybe_ref(code)
                            .store_maybe_ref(data)
                            .store_dict(None)
                            .end_cell().hash)

        addr_obj = Address((TonV3R2AddrEncoderConst.WORKCHAIN, hash))
        return addr_obj.to_str(is_bounceable=is_bounceable)
