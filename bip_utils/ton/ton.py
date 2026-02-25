# Copyright (c) 2022 Emanuele Bellocchia
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

"""Module containing utility classes for Ton keys derivation."""

# Imports
from __future__ import annotations

from typing import Optional
 

from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PrivateKey
from bip_utils.ton.address.ton_address_encoder import TonAddressEncoder

class Ton:
    

    def __init__(self):
        """
        Construct class.
        """

    def FromSeed(self, seed_bytes: bytes):
        """
        Construct class from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            ElectrumV2Base object: ElectrumV2Base object
        """
        self.private_key = Ed25519PrivateKey.FromBytes(seed_bytes[:32]).UnderlyingObject()
        return self
    
     

    def GetPublicKey(self) -> bytes:
        """
        Get public key from seed. The public key is the last 32 bytes of the seed.

        Returns:
            Ed25519PublicKey: Generated public key
        """
        return self.private_key.verify_key.encode()
    
    def GetPrivateKey(self) -> bytes:
        """
        Get private key from seed.

        Returns:
            Ed25519PrivateKey: Generated private key
        """
        return self.private_key.encode()
    
    def GetAddress(self, version: Optional[str] = "v5r1", is_bounceable: Optional[bool] = False) -> str:
        """
        Get address

        Returns:
            str: Generated address
        """
        
        public_key = self.ToPublicKey()

        address = TonAddressEncoder(public_key, version=version, is_bounceable=is_bounceable).encode()
        return address
