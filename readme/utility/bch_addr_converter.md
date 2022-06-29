## Bitcoin Cash address converter

The Bitcoin Cash address converter library allows converting Bitcoin Cash addresses, by changing the HRP and net version.

**Code example**

    from bip_utils import BchAddrConverter

    # Convert address by change the HRP (the old net version is maintained)
    conv_addr = BchAddrConverter.Convert("bitcoincash:qp90dvzptg759efdcd93s4dkdw0vuhlkmqlch7letq", hrp="ergon")
    # Convert address by change both HRP and net version
    conv_addr = BchAddrConverter.Convert("bitcoincash:qp90dvzptg759efdcd93s4dkdw0vuhlkmqlch7letq", hrp="customprefix", net_ver=b"\x01")
