#!/usr/bin/env python

import os
import sys

from setuptools import setup, find_packages

if sys.version_info.major == 3 and sys.version_info.minor < 3:
    print("Unfortunately, your python version is not supported!\n Please upgrade at least to python 3.3!",
          file = sys.stderr)
    sys.exit(1)

if sys.platform == 'darwin' or sys.platform == 'win32':
    print("Unfortunately, we do not support your platform %s" % sys.platform,
          file = sys.stderr)
    sys.exit(1)

# Install Androguard - if you have a better solution, feel free to fix the shitty workaround
os.system('pip install git+https://github.com/androguard/androguard.git@v3.1.0-pre.2')

install_requires = [
    "asn1crypto==0.24.0",
    "cffi==1.11.2",
    "cryptography==2.1.4",
    "decorator==4.1.2",
    "future==0.16.0",
    "idna==2.6",
    "ipython==6.2.1",
    "ipython-genutils==0.2.0",
    "jedi==0.11.1",
    "lxml==4.1.1",
    "networkx==2.0",
    "parso==0.1.1",
    "pexpect==4.3.1",
    "pickleshare==0.7.4",
    "prompt-toolkit==1.0.15",
    "ptyprocess==0.5.2",
    "pyasn1==0.4.2",
    "pycparser==2.18",
    "Pygments==2.2.0",
    "requests==2.18.4",
    "simplegeneric==0.8.1",
    "six==1.11.0",
    "traitlets==4.3.2",
    "wcwidth==0.1.7",
]

data_dir = os.path.join('exodus_core', 'analysis', 'dexdump')
data_files = [(d, [os.path.join(d, f) for f in files])
             for d, folders, files in os.walk(data_dir)]

setup(name = 'exodus_core',
      version = '1.0',
      description = 'Core functionality of εxodus',
      author = 'Exodus Privacy',
      author_email = 'contact@exodus-privacy.eu.org',
      url = 'https://github.com/Exodus-Privacy/exodus-core',
      packages = find_packages(exclude = ["*.tests", "*.tests.*", "test*", "tests"]),
      data_files = data_files,
      install_requires = install_requires,
      include_package_data = True,
      zip_safe = False,
      )
