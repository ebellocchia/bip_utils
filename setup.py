import setuptools
import re
from setuptools.command.install import install
from setuptools.command.develop import develop


# File names
DESCRIPTION_FILE = "README.md"
KEYWORDS_FILE = "keywords.txt"
REQUIREMENTS_FILE = "requirements.txt"
VERSION_FILE = "bip_utils/_version.py"


# Load long description
def load_long_description():
    return open(DESCRIPTION_FILE).read()


# Load keywords
def load_keywords():
    with open(KEYWORDS_FILE, "r") as fin:
        return ", ".join([line for line in map(str.strip, fin.read().splitlines())
                          if len(line) > 0 and not line.startswith("#")])


# Load version
def load_version():
    version_line = open(VERSION_FILE).read().rstrip()
    vre = re.compile(r'__version__: str = "([^"]+)"')
    matches = vre.findall(version_line)

    if matches and len(matches) > 0:
        return matches[0]
    else:
        raise RuntimeError(f"Cannot find version string in {VERSION_FILE}")


# Load requirements
def load_requirements():
    with open(REQUIREMENTS_FILE, "r") as fin:
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


# Load needed files
long_description = load_long_description()
keywords = load_keywords()
install_requires = load_requirements()
version = load_version()


# Setup configuration
setuptools.setup(
    name="bip_utils",
    version=version,
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Implementation of BIP39, BIP32, BIP44, BIP49 and BIP84 for wallet seeds, keys and addresses generation.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/bip_utils",
    download_url="https://github.com/ebellocchia/bip_utils/archive/v%s.tar.gz" % version,
    license="MIT",
    test_suite="tests",
    cmdclass={
        "install": InstallCommand,
        "develop": DevelopCommand,
    },
    install_requires=install_requires,
    packages=setuptools.find_packages(exclude=["tests"]),
    package_data={
        "bip_utils": [
            # BIP39
            "bip/bip39/bip39_words/english.txt",
            "bip/bip39/bip39_words/italian.txt",
            "bip/bip39/bip39_words/french.txt",
            "bip/bip39/bip39_words/spanish.txt",
            "bip/bip39/bip39_words/portuguese.txt",
            "bip/bip39/bip39_words/czech.txt",
            "bip/bip39/bip39_words/chinese_simplified.txt",
            "bip/bip39/bip39_words/chinese_traditional.txt",
            "bip/bip39/bip39_words/korean.txt",
            # Monero
            "monero/mnemonic/monero_words/chinese_simplified.txt",
            "monero/mnemonic/monero_words/dutch.txt",
            "monero/mnemonic/monero_words/english.txt",
            "monero/mnemonic/monero_words/french.txt",
            "monero/mnemonic/monero_words/german.txt",
            "monero/mnemonic/monero_words/italian.txt",
            "monero/mnemonic/monero_words/japanese.txt",
            "monero/mnemonic/monero_words/portuguese.txt",
            "monero/mnemonic/monero_words/russian.txt",
            "monero/mnemonic/monero_words/spanish.txt",
        ]
    },
    keywords=keywords,
    platforms=["any"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
)
