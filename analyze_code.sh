#!/bin/bash

isort .
flake8 .
mypy .
prospector .
