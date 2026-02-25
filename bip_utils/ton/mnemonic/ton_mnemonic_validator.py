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

"""Module for Algorand mnemonic validation."""

# Imports
from typing import Optional


from bip_utils.bip.bip39.bip39_mnemonic import Bip39Languages
from bip_utils.utils.crypto.hmac import HmacSha512
from bip_utils.utils.crypto.pbkdf2 import Pbkdf2HmacSha512
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter

class TonMnemonicValidator:
    """
    TON mnemonic validator class.
    It validates a mnemonic phrase.
    See https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts
    """

    def __init__(self):
        """
        Construct class.
        """


    def IsValid(self, mnemonic: str, passphrase: Optional[str] = "") -> bool:
        entropy =  HmacSha512().QuickDigest(mnemonic, passphrase)
        mnemonic_array =  mnemonic.split(" ")
        words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)
        for word in mnemonic_array:
            try:
                words_list.GetWordIdx(word)
            except ValueError:      
                return False
        if passphrase != "":
            seed = Pbkdf2HmacSha512().DeriveKey(entropy, "TON fast seed version", 1, 64)
            return seed[0] == 1
        else:
            seed = Pbkdf2HmacSha512().DeriveKey(entropy, "TON seed version", 390, 64)
            return seed[0] == 0
    
       

         

       