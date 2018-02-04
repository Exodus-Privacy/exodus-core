#!/usr/bin/env python

import os
import sys

from setuptools import setup, find_packages

if sys.version_info.major == 3 and sys.version_info.minor < 3:
    print("Unfortunately, your python version is not supported!\n Please upgrade at least to python 3.3!")
    sys.exit(1)

if sys.platform == 'darwin' or sys.platform == 'win32':
    print("Unfortunately, we do not support your platform %s" % sys.platform)
    sys.exit(1)

# Install Androguard - if you have a better solution, feel free to fix the shitty workaround
os.system('pip install git+https://github.com/androguard/androguard.git@v3.1.0-pre.2')

install_requires = [
    "requests==2.18.4",
    "Pillow==5.0.0",
    "dhash==1.3",
    "jellyfish==0.5.6",
]

data_dir = os.path.join('exodus_core', 'analysis', 'dexdump')
data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(data_dir)]

setup(name = 'exodus_core',
      version = '1.0.5',
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
