import setuptools
import re

VERSION_FILE = "bip_utils/_version.py"

with open("README.md", "r") as f:
    long_description = f.read()

def load_version():
    version_line = open(VERSION_FILE).read().rstrip()
    vre = re.compile(r'__version__: str = "([^"]+)"')
    matches = vre.findall(version_line)

    if matches and len(matches) > 0:
        return matches[0]
    else:
        raise RuntimeError("Cannot find version string in %s" % VERSION_FILE)

version = load_version()

setuptools.setup(
    name="bip_utils",
    version=version,
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Implementation of BIP39, BIP32, BIP44, BIP49 and BIP84 for wallet seeds, keys and addresses generation. Supported coins: Bitcoin, Bitcoin Cash, BitcoinSV, Litecoin, Dogecoin, Dash, Zcash, Ethereum, Ethereum Classic, VeChain, Ripple, Tron, Cosmos, Band Protocol, Kava, IRIS Network, Terra, Binance Chain, Binance Smart Chain, Avalanche, Polygon, Fantom Opera, Harmony One, Huobi Chain, OKEx Chain.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/bip_utils",
    download_url="https://github.com/ebellocchia/bip_utils/archive/v%s.tar.gz" % version,
    license="MIT",
    test_suite="tests",
    install_requires = ["ecdsa>=0.14","pysha3"],
    packages=setuptools.find_packages(exclude=['tests']),
    package_data={"bip_utils": ["bip/bip39_words/english.txt", "bip/bip39_words/italian.txt", "bip/bip39_words/french.txt", "bip/bip39_words/spanish.txt", "bip/bip39_words/portuguese.txt", "bip/bip39_words/czech.txt", "bip/bip39_words/chinese_simplified.txt", "bip/bip39_words/chinese_traditional.txt", "bip/bip39_words/korean.txt"]},
    keywords="bitcoin, bitcoin cash, bitcoinsv, litecoin, dogecoin, dash, zcash, ethereum, ethereum classic, vechain, ripple, tron, cosmos, atom, band protocol, kava, iris, irisnet, terra, binance chain, binance smart chain, bnb, avalanche, avax, polygon, matic, fantom opera, harmony one, huobi chain, okex chain, wallet, hd-wallet, bip39, bip32, bip44, bip49, bip84, python",
    platforms = ["any"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.6",
)
