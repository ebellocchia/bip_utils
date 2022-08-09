import importlib
from pathlib import Path


# Quick check if all examples work
for f in Path("examples").glob("*.py"):
    importlib.import_module(f.name.replace(".py", ""))
