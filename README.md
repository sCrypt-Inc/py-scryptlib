# scryptlib-python
A Python SDK for [sCrypt](https://scrypt.io/).

[![Build Status](https://travis-ci.com/kala-tech/scryptlib-python.svg?branch=main)](https://travis-ci.com/kala-tech/scryptlib-python)

## Installation

To use the SDK, you need to get a copy of the [sCrypt compiler](https://scrypt.io/#download).

You can install the SDK as a Python package using `pip`, either directly from the project folder:

```sh
pip install .
```

, or from the PyPI:

```sh
pip install scryptlib
```

## Usage

The SDK is used to convert script templates, produced by the sCrypt compiler, to an object-based representation in Python. It allows for easy compilation, inspection and verification of smart contracts.

### Example contract verification

TODO

You can learn more about writing sCrypt smart contracts in the official [docs](https://scryptdoc.readthedocs.io/en/latest/intro.html).

## Testing

The SDK has a suite of unit tests, which you can run by executing the `pytest` command in the root of the project.
