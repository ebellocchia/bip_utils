import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="bip_utils",
    version="0.4.1",
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Implementation of BIP39, BIP32, BIP44, BIP49 and BIP84 for wallet seeds, keys and addresses generation. Supported coins: Bitcoin, Litecoin, Dogecoin, Ethereum.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/bip_utils",
    download_url="https://github.com/ebellocchia/bip_utils/archive/v0.4.1.tar.gz",
    license="MIT",
    test_suite="tests",
    install_requires = ["ecdsa","pysha3"],
    packages=["bip_utils"],
    package_data={"bip_utils": ["bip39_wordslist_en.txt"]},
    keywords="bitcoin, litecoin, dogecoin, dash, ethereum, ripple, wallet, hd-wallet, bip39, bip32, bip44, bip49, bip84, python",
    platforms = ["any"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.6",
)
