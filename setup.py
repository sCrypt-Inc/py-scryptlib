#!/usr/bin/env python

import codecs
from setuptools import setup
from os import path


def read(rel_path):
    here = path.abspath(path.dirname(__file__))
    with codecs.open(path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else '\''
            return line.split(delim)[1]
    else:
        raise RuntimeError('Unable to find version string.')


here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(long_description=long_description,
      long_description_content_type="text/markdown",
      name='scryptlib',
      version=get_version('scryptlib/__init__.py'),
      description='Python SDK for integration of sCrypt Bitcoin SV smart contracts.',
      keywords='scrypt scryptlib bitcoin bsv blockchain',
      author='Kala',
      url='https://www.github.com/kala-tech/scryptlib-python',
      packages=['scryptlib'],
      install_requires=['bitcoinX'],
      python_requires='>=3.7',

      # Dependencies to run all tests.
      extras_require = {
        'testing': ['rabin', 'ecdsa']
      }
     )
