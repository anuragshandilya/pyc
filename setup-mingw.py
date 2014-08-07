#!/usr/bin/env python
from distutils.core import setup, Extension
from sys import platform
from os import environ

CFLAGS = [ '-Wall', '-O2', '-fno-strict-aliasing' ]
LDFLAGS = [ '-L.' ]
LIBS = [ 'clamav' ]
CLINCLUDE = [ '.' ]
CLLIB = []

pyc = Extension('pyc',
                sources = ['pyc.c'],
                libraries = LIBS,
                extra_objects = CLLIB,
                extra_link_args = LDFLAGS,
                extra_compile_args = CFLAGS)

# Build : python setup.py build
# Install : python setup.py install
# Register : python setup.py register

# python setup-mingw.py build --compiler=mingw32

setup (name = 'pyc',
       version = '0.98.4',
       author = 'Gianluigi Tiesi',
       author_email = 'sherpya@netfarm.it',
       license ='GPL',
       keywords="python, clamav, antivirus, scanner, virus, libclamav",
       include_dirs = CLINCLUDE,
       ext_modules = [ pyc ])
