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
Module containing utility classes for TON V4 address computation.

Reference: https://github.com/ton-org/ton/blob/main/src/wallets/v4/WalletContractV4.ts
"""

# Imports
from pytoniq_core import Address, Cell, begin_cell

from bip_utils.ton.ton_keys import TonPublicKey
from bip_utils.utils.misc import Base64Decoder


class TonV4AddrEncoderConst:
    """Class container for Ton V4 address encoder constants."""

    CONTRACT_CODE: bytes = Base64Decoder.Decode("te6ccgECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVA==") # noqa: E501
    WORKCHAIN: int = 0


class TonV4AddrEncoder:
    """TON V4 address encoder class."""

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
        Encode public key to V4 address.

        Args:
            is_bounceable (bool): Whether the address is bounceable

        Returns:
            str: Address string
        """
        wallet_id = 698983191 + TonV4AddrEncoderConst.WORKCHAIN

        code = Cell.one_from_boc(TonV4AddrEncoderConst.CONTRACT_CODE)

        data = (begin_cell().store_uint(0, 32)
                            .store_uint(wallet_id, 32)
                            .store_bytes(self.m_pub_key)
                            .store_bit(0)
                            .end_cell())

        hash = (begin_cell().store_bit(False)
                            .store_bit(False)
                            .store_maybe_ref(code)
                            .store_maybe_ref(data)
                            .store_dict(None)
                            .end_cell().hash)

        addr_obj = Address((TonV4AddrEncoderConst.WORKCHAIN, hash))
        return addr_obj.to_str(is_bounceable=is_bounceable)
