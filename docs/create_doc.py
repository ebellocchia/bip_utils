# Helper script to automatically create the doc folder
# Author: Emanuele Bellocchia

#
# Imports
#
import os
import shutil
from typing import List

#
# Constants
#
PROJECT: str = "bip_utils"

DOC_FOLDER: str = os.path.join(".", PROJECT)
SRC_FOLDER: str = os.path.join("..", PROJECT)

DOC_EXT: str = ".rst"
SRC_EXT: str = ".py"

DOC_INDEX_FILE: str = "index" + DOC_EXT

UNDERLINE_CHAR: str = "="

TOCTREE_MAX_DEPTH: int = 10

DOC_FILE_TEMPLATE: str = """{module_name}
{title_underline}

.. automodule:: {module_path}
   :members:
   :undoc-members:
   :show-inheritance:
"""

DOC_INDEX_TEMPLATE: str = """{index_name}
{title_underline}
.. toctree::
   :maxdepth: {toctree_max_depth}

{modules_list}
"""


#
# Functions
#

def create_doc_main_dir() -> None:
    shutil.rmtree(DOC_FOLDER, ignore_errors=True)
    os.mkdir(DOC_FOLDER)


def is_dir_empty(d: str) -> bool:
    return listdir_dirs(d) == [] and listdir_files(d) == []


def is_dir_valid(d: str) -> bool:
    return not os.path.basename(d).startswith(("__", "."))


def is_file_valid(f: str) -> bool:
    return not os.path.basename(f).startswith(("_", ".")) and f.find(SRC_EXT) != -1


def listdir_files(d: str) -> List[str]:
    elems = [os.path.join(d, e) for e in os.listdir(d)]
    return [e for e in elems
            if os.path.isfile(e) and is_file_valid(e)]


def listdir_dirs(d: str) -> List[str]:
    elems = [os.path.join(d, e) for e in os.listdir(d)]
    return [e for e in elems
            if os.path.isdir(e) and is_dir_valid(e) and not is_dir_empty(e)]


def src_to_doc_path(p: str) -> str:
    return p.replace(SRC_FOLDER, DOC_FOLDER)


def src_to_doc_file(f: str) -> str:
    return src_to_doc_path(f).replace(SRC_EXT, DOC_EXT)


def create_doc_dir(d: str) -> None:
    doc_dir = src_to_doc_path(d)
    os.mkdir(doc_dir)
    print(f"Create doc directory: {doc_dir}")


def get_index_name(f: str) -> str:
    return os.path.basename(f)


def get_index_modules_list(dirs: List[str], files: List[str]) -> str:
    elems = list(map(lambda f: "   " + get_module_name(f) + "/" + DOC_INDEX_FILE, dirs)) + \
            list(map(lambda f: "   " + get_module_name(f), files))
    elems.sort()

    return "\n".join(elems)


def get_module_name(f: str) -> str:
    return os.path.basename(f).replace(DOC_EXT, "").replace(SRC_EXT, "")


def get_module_path(f: str) -> str:
    return PROJECT + "." + f.replace(DOC_EXT, "").replace(DOC_FOLDER, "").replace("/", ".").replace("\\", ".")[1:]


def get_title_underline(m: str) -> str:
    return UNDERLINE_CHAR * len(m)


def create_doc_file(f: str) -> None:
    doc_file = src_to_doc_file(f)
    with open(doc_file, "w") as fout:
        module_name = get_module_name(doc_file)
        fout.write(DOC_FILE_TEMPLATE.format(module_name=module_name,
                                            title_underline=get_title_underline(module_name),
                                            module_path=get_module_path(doc_file)))

        print(f"Create doc file: {doc_file}")


def create_doc_index(d: str, dirs: List[str], files: List[str]) -> None:
    if len(dirs) == 0 and len(files) == 0:
        return

    index_file = os.path.join(src_to_doc_path(d), DOC_INDEX_FILE)
    with open(index_file, "w") as fout:
        index_name = get_index_name(d)
        fout.write(DOC_INDEX_TEMPLATE.format(index_name=index_name,
                                             title_underline=get_title_underline(index_name),
                                             toctree_max_depth=TOCTREE_MAX_DEPTH,
                                             modules_list=get_index_modules_list(dirs, files)))
        print(f"Create index file: {index_file}")


def create_doc(d: str) -> None:
    files = listdir_files(d)
    dirs = listdir_dirs(d)

    for f in files:
        create_doc_file(f)

    create_doc_index(d, dirs, files)

    for d in dirs:
        create_doc_dir(d)
        create_doc(d)


#
# Script
#

create_doc_main_dir()
create_doc(SRC_FOLDER)
