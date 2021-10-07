# scryptlib-python
A Python SDK for [sCrypt](https://scrypt.io/).

[![Build Status](https://app.travis-ci.com/sCrypt-Inc/py-scryptlib.svg?branch=main)](https://travis-ci.com/sCrypt-Inc/py-scryptlib)

You can learn all about writing sCrypt smart contracts in the official [docs](https://scryptdoc.readthedocs.io/en/latest/intro.html).

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

### Compiling an sCrypt contract

We can compile an sCrypt conract source file like so:

```python
import scryptlib.utils

contract = './test/res/arraydemo.scrypt'
compiler_result = scryptlib.utils.compile_contract(contract)
```

This will leave us with a `CompilerResult` object, that contains all of the data, returned by the compiler.
The `compile_contract` method will try to automatically search for the compiler binary. You can also explicitly pass the path to the binary, using the `compiler_bin` parameter.

It is also possible to pass the sCrypt source code as a string object:

```python
contract_source = '''
    contract Equals {
        int x;

        constructor(int x) {
            this.x = x;
        }

        public function equals(int y) {
            require(this.x == y);
        }

    }
'''

compiler_result = scryptlib.utils.compile_contract(contract_source, from_string=True)
```

The resulting **contract description file** will be written to `./out` by default. That may also be changed with the `out_dir` parameter.
You can access the contract description directly from the `CompilerResult` with its `to_desc()` method.

### Evaluating a contract locally

We can evaluate any public function of the contract locally on our machine, before broadcasting it.

First we need to create a class representation of the contract and instantiate it:

```python
import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int

EQUAL_VAL = 2021

contract = './test/res/equals.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Equals = scryptlib.contract.build_contract_class(desc)
contract_obj = Equals(Int(EQUAL_VAL))
```

As we can see, the created class takes the contract parameters in the constructor. In the case of the `Equals` contract, that is an sCrypt `int` type, which we can represent in Python using an instance of `scryptlib.types.Int`.

Once we have an instance of the contract class, we can evaluate its public functions:

```python
verify_result = contract_obj.equals(Int(EQUAL_VAL)).verify()
assert verify_result == True
```

From the example see, that we called the contracts public function, named `equals`. The actual call to `equals()` in Python reutrns an instance of `scryptlib.abi.FunctionCall`. That object in turn has a method, named `verify`, with which we can run the function calls unlocking script against the contracts locking script.
`verify` can internaly create an input evaluation context for simple contracts, but once we start using more advanced constructs, like signatures, we can pass an instance of `bitconx.TxInputContext`, using the `tx_input_context` parameter.

sctyptlib-python leverages the [bitcoinx](https://github.com/kyuupichan/bitcoinX) library to deal with Bitcoin primitives.

The following is an example of a local evaluation of a P2PKH contract:

```python
import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte


key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub = key_priv.public_key
pubkey_hash = key_pub.hash160()

contract = './test/res/p2pkh.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

P2PKH = scryptlib.contract.build_contract_class(desc)
p2pkh_obj = P2PKH(Ripemd160(pubkey_hash))

context = scryptlib.utils.create_dummy_input_context()

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0
utxo_satoshis = context.utxo.value
sighash = context.tx.signature_hash(input_idx, utxo_satoshis, p2pkh_obj.locking_script, sighash_flag)

sig = key_priv.sign(sighash, hasher=None)
sig = sig + pack_byte(sighash_flag)

verify_result = p2pkh_obj.unlock(Sig(sig), PubKey(key_pub)).verify(context)
assert verify_result == True
```

## Testing

The SDK has a suite of unit tests, which we can run by executing the `pytest` command in the root of the project.
