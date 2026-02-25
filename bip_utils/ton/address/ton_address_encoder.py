

import base64
from enum import StrEnum, unique
from  pytoniq_core import Cell, begin_cell, Address
from typing import List

wallet_versions_serialisation = {
        "v5r1": 0
    }


@unique
class TonAddressVerions(StrEnum):
    """Enumerative for TON address versions."""

    V5R1 = "v5r1"
    V4 = "v4"
    V3R2 = "v3r2"
    V3R1 = "v3r1"


class TonAddressConst:
    """Class container for TON address constants."""

    # Accepted addrsess versions
    TON_ADDRESS_VERSIONS: List[TonAddressVerions] = [
        TonAddressVerions.V5R1,  
        TonAddressVerions.V4,
        TonAddressVerions.V3R2,
        TonAddressVerions.V3R1
    ]


class TonAddressEncoder:
    """
    TON address encoder class.
    See for source: 
    https://github.com/ton-org/ton/blob/main/src/wallets/v5r1/WalletContractV5R1.ts
    https://github.com/ton-org/ton/blob/main/src/wallets/v4/WalletContractV4.ts
    https://github.com/ton-org/ton/blob/main/src/wallets/v3/r2.ts
    https://github.com/ton-org/ton/blob/main/src/wallets/v3/r1.ts
    """  
       
    def __init__(self, public_key, version="v5r1", is_bounceable=False):
        if version not in TonAddressConst.TON_ADDRESS_VERSIONS:
            raise ValueError(f"Version ({version}) is not valid. Supported versions are: {', '.join(TonAddressConst.TON_ADDRESS_VERSIONS)}")
        self.public_key = public_key
        self.is_bounceable = is_bounceable
        self.version = version

    def v5r1Address(self):
        
        wallet_details =  {
                        "workchain": 0,
                        "walletVersion": "v5r1",
                        "subwalletNumber": 0,
                        "networkGlobalId": -239
                    }
        
        
        code = Cell.one_from_boc("b5ee9c7241021401000281000114ff00f4a413f4bcf2c80b01020120020d020148030402dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e2100f020120050c020120060902016e07080019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00201480a0b0017b325fb51341c75c875c2c7e00011b262fb513435c280200019be5f0f6a2684080a0eb90fa02c0102f20e011e20d70b1f82107369676ebaf2e08a7f0f01e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd81003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0b4d6c35e")
        
        context =  begin_cell() .store_uint(1, 1)\
        .store_int(wallet_details["workchain"] , 8)\
        .store_uint(wallet_versions_serialisation[wallet_details["walletVersion"]], 8)\
        .store_uint(wallet_details["subwalletNumber"], 15).end_cell().begin_parse().load_int(32)
            
        data = begin_cell().store_uint(1,1)\
                        .store_uint(0, 32)\
                        .store_int(wallet_details["networkGlobalId"] ^ context, 32)\
                        .store_bytes(self.public_key)\
                        .store_bit(0) \
                    .end_cell()
                            
        
        hash_ =   begin_cell().store_bit(False).store_bit(False).store_maybe_ref(code)\
                .store_maybe_ref(data)\
                    .store_dict(None)\
            .end_cell().hash
            
        add = Address((wallet_details["workchain"], hash_))
        return add.to_str(is_bounceable=self.is_bounceable)

    def v4Address(self):
        
            wallet_details =  {"workchain": 0}
        
            wallet_id = 698983191 + wallet_details["workchain"]

            code = Cell.one_from_boc(base64.b64decode("te6ccgECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVA=="))
            
            
            data = begin_cell()\
                            .store_uint(0, 32)\
                            .store_uint(wallet_id, 32)\
                            .store_bytes(self.public_key)\
                            .store_bit(0) \
                        .end_cell()
                                
            
            hash_ =   begin_cell().store_bit(False).store_bit(False).store_maybe_ref(code)\
                .store_maybe_ref(data)\
                    .store_dict(None)\
            .end_cell().hash
            
            add = Address((wallet_details["workchain"], hash_))
            return add.to_str(is_bounceable=self.is_bounceable)


    def v3r2Address(self):
        
            wallet_details =  {"workchain": 0}

            wallet_id = 698983191 + wallet_details["workchain"]

            code = Cell.one_from_boc(base64.b64decode("te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0="))
            
            
            data = begin_cell()\
                            .store_uint(0, 32)\
                            .store_uint(wallet_id, 32)\
                            .store_bytes(self.public_key)\
                        .end_cell()
                                
            
            hash_ =   begin_cell().store_bit(False).store_bit(False).store_maybe_ref(code)\
                    .store_maybe_ref(data)\
                        .store_dict(None)\
                .end_cell().hash
                
            add = Address((wallet_details["workchain"], hash_))
            return add.to_str(is_bounceable=self.is_bounceable)

    def v3r1Address(self):
            wallet_details =  {"workchain": 0}

            wallet_id = 698983191 + wallet_details["workchain"]

            code = Cell.one_from_boc(base64.b64decode("te6cckEBAQEAYgAAwP8AIN0gggFMl7qXMO1E0NcLH+Ck8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVD++buA="))
            
            
            data = begin_cell()\
                            .store_uint(0, 32)\
                            .store_uint(wallet_id, 32)\
                            .store_bytes(self.public_key)\
                        .end_cell()
                                
            
            hash_ =   begin_cell().store_bit(False).store_bit(False).store_maybe_ref(code)\
                    .store_maybe_ref(data)\
                        .store_dict(None)\
                .end_cell().hash
                
            add = Address((wallet_details["workchain"], hash_))
            return add.to_str(is_bounceable=self.is_bounceable)
    
    def encode(self):
        if self.version == "v5r1":
            return self.v5r1Address()
        elif self.version == "v4":
            return self.v4Address()
        elif self.version == "v3r2":
            return self.v3r2Address()
        else:
            return self.v3r1Address()