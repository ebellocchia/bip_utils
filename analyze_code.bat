pip install -r requirements-dev.txt

isort .
flake8 .
mypy .
prospector .
