#!/usr/bin/env python

import os
import sys

from setuptools import setup, find_packages


def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


if sys.version_info.major == 3 and sys.version_info.minor < 3:
    print("Unfortunately, your python version is not supported!\n Please upgrade at least to python 3.3!")
    sys.exit(1)

if sys.platform == 'darwin' or sys.platform == 'win32':
    print("Unfortunately, we do not support your platform %s" % sys.platform)
    sys.exit(1)

if which('dexdump') is None:
    print("Unable to find dexdump executable, please install it.")
    print("On Debian-like OS, run sudo apt-get install dexdump")
    sys.exit(1)

install_requires = [
    'androguard==3.3.5',
    'cryptography==3.3.2',
    'dhash==1.3',
    'jellyfish==0.5.6',
    'Pillow==6.2.2',
    'requests==2.21.0',
    'six==1.15.0',
    'traitlets==4.3.2'
]

setup(
    name='exodus_core',
    version='1.3.3',
    description='Core functionality of εxodus',
    author='Exodus Privacy',
    author_email='contact@exodus-privacy.eu.org',
    url='https://github.com/Exodus-Privacy/exodus-core',
    packages=find_packages(exclude=["*.tests", "*.tests.*", "test*", "tests"]),
    install_requires=install_requires,
    include_package_data=True,
    zip_safe=False,
)
