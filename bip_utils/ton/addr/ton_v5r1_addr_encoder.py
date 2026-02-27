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
Module containing utility classes for TON V5R1 address.

Reference: https://github.com/ton-org/ton/blob/main/src/wallets/v5r1/WalletContractV5R1.ts
"""

# Imports
from pytoniq_core import Address, Cell, begin_cell

from bip_utils.ton.ton_keys import TonPublicKey


class TonV5R1AddrEncoderConst:
    """Class container for Ton V5R1 address encoder constants."""

    CONTRACT_CODE: str = "b5ee9c7241021401000281000114ff00f4a413f4bcf2c80b01020120020d020148030402dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e2100f020120050c020120060902016e07080019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00201480a0b0017b325fb51341c75c875c2c7e00011b262fb513435c280200019be5f0f6a2684080a0eb90fa02c0102f20e011e20d70b1f82107369676ebaf2e08a7f0f01e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd81003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0b4d6c35e" # noqa: E501
    NETWORK_GLOBAL_ID: int = -239
    SUBWALLET_NUMBER: int = 0
    WORKCHAIN: int = 0


class TonV5R1AddrEncoder:
    """TON V5R1 address encoder class."""

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
        Encode public key to V5R1 address.

        Args:
            is_bounceable (bool): Whether the address is bounceable

        Returns:
            str: Address string
        """
        code = Cell.one_from_boc(TonV5R1AddrEncoderConst.CONTRACT_CODE)

        context = (begin_cell().store_uint(1, 1)
                               .store_int(TonV5R1AddrEncoderConst.WORKCHAIN, 8)
                               .store_uint(0, 8)
                               .store_uint(TonV5R1AddrEncoderConst.SUBWALLET_NUMBER, 15)
                               .end_cell()
                               .begin_parse()
                               .load_int(32))

        data = (begin_cell().store_uint(1, 1)
                            .store_uint(0, 32)
                            .store_int(TonV5R1AddrEncoderConst.NETWORK_GLOBAL_ID ^ context, 32)
                            .store_bytes(self.m_pub_key)
                            .store_bit(0)
                            .end_cell())

        hash = (begin_cell().store_bit(False)
                            .store_bit(False)
                            .store_maybe_ref(code)
                            .store_maybe_ref(data)
                            .store_dict(None)
                            .end_cell().hash)

        addr_obj = Address((TonV5R1AddrEncoderConst.WORKCHAIN, hash))
        return addr_obj.to_str(is_bounceable=is_bounceable)
