import os
import re

import setuptools
from setuptools.command.develop import develop
from setuptools.command.install import install


# Load long description
def load_long_description(desc_file):
    return open(desc_file, encoding='utf-8').read()


# Load keywords
def load_keywords(keywords_file):
    with open(keywords_file, "r") as fin:
        return ", ".join([line for line in map(str.strip, fin.read().splitlines())
                          if len(line) > 0 and not line.startswith("#")])


# Load version
def load_version(*path_parts):
    version_file = os.path.join(*path_parts)
    version_line = open(os.path.join(*path_parts)).read().rstrip()
    vre = re.compile(r'__version__: str = "([^"]+)"')
    matches = vre.findall(version_line)

    if matches and len(matches) > 0:
        return matches[0]

    raise RuntimeError(f"Cannot find version string in {version_file}")


# Load requirements
def load_requirements(req_file):
    with open(req_file, "r") as fin:
        return [line for line in map(str.strip, fin.read().splitlines())
                if len(line) > 0 and not line.startswith("#")]


# Command base class
class CommandBase(object):
    conf_file = "bip_utils/ecc/conf.py"
    conf_str = "USE_COINCURVE: bool = "

    user_options = [
        ("coincurve=", None, "1 to use coincurve library for secp256k1, 0 for using ecdsa library for secp256k1"),
    ]

    def initialize_options(self):
        super().initialize_options()
        self.coincurve = 1

    def finalize_options(self):
        self.coincurve = self.__validate_and_get_coincurve_param()
        super().finalize_options()

    def run(self):
        print(f"Coincurve: {'enabled' if self.coincurve else 'disabled'}")
        self.__write_conf_file()
        super().run()

    def __validate_and_get_coincurve_param(self):
        try:
            param = int(self.coincurve)
        except ValueError:
            raise ValueError(f"Invalid coincurve option value {self.coincurve}")

        if param not in (0, 1):
            raise ValueError(f"Invalid coincurve option value {self.coincurve}")

        return param

    def __write_conf_file(self):
        with open(self.conf_file, "r") as fin:
            file_content = fin.read()

        coincurve_str = "True" if self.coincurve else "False"

        conf_idx = file_content.index(self.conf_str)
        nl_idx = file_content.index("\n", conf_idx)

        # Re-write the py file with the updated string
        # Probably not the best solution, but I'm not very familiar with install options
        file_content = file_content.replace(file_content[conf_idx:nl_idx], self.conf_str + coincurve_str, 1)

        with open(self.conf_file, "w") as fout:
            fout.write(file_content)


# Install command class
class InstallCommand(CommandBase, install):
    user_options = getattr(install, 'user_options', []) + CommandBase.user_options


# Develop command class
class DevelopCommand(CommandBase, develop):
    user_options = getattr(develop, 'user_options', []) + CommandBase.user_options


# Load version
version = load_version("bip_utils", "_version.py")

# Setup configuration
setuptools.setup(
    name="bip_utils",
    version=version,
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Generation of mnemonics, seeds, private/public keys and addresses for different types of cryptocurrencies",
    long_description=load_long_description("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/bip_utils",
    download_url="https://github.com/ebellocchia/bip_utils/archive/v%s.tar.gz" % version,
    license="MIT",
    test_suite="tests",
    cmdclass={
        "install": InstallCommand,
        "develop": DevelopCommand,
    },
    install_requires=load_requirements("requirements.txt"),
    extras_require={
        "develop": load_requirements("requirements-dev.txt"),
    },
    packages=setuptools.find_packages(exclude=["*tests*"]),
    package_data={
        "bip_utils": [
            # BIP39
            "bip/bip39/wordlist/english.txt",
            "bip/bip39/wordlist/italian.txt",
            "bip/bip39/wordlist/french.txt",
            "bip/bip39/wordlist/spanish.txt",
            "bip/bip39/wordlist/portuguese.txt",
            "bip/bip39/wordlist/czech.txt",
            "bip/bip39/wordlist/chinese_simplified.txt",
            "bip/bip39/wordlist/chinese_traditional.txt",
            "bip/bip39/wordlist/korean.txt",
            # Electrum
            "electrum/mnemonic_v1/wordlist/english.txt",
            # Monero
            "monero/mnemonic/wordlist/chinese_simplified.txt",
            "monero/mnemonic/wordlist/dutch.txt",
            "monero/mnemonic/wordlist/english.txt",
            "monero/mnemonic/wordlist/french.txt",
            "monero/mnemonic/wordlist/german.txt",
            "monero/mnemonic/wordlist/italian.txt",
            "monero/mnemonic/wordlist/japanese.txt",
            "monero/mnemonic/wordlist/portuguese.txt",
            "monero/mnemonic/wordlist/russian.txt",
            "monero/mnemonic/wordlist/spanish.txt",
        ]
    },
    keywords=load_keywords("keywords.txt"),
    platforms=["any"],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
)
