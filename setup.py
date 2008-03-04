#!/usr/bin/env python
from distutils.core import setup, Extension
from sys import platform
from os import environ

if platform == 'win32':
    CFLAGS = ['/LD']
    LIBS = []
    CLAMAVDEVROOT = environ.get('CLAMAV_DEVROOT')
    DEBUG = environ.get('CLAMAV_DEBUG', None)
    if DEBUG is not None:
        LIBFILE = 'contrib/msvc/Debug/Win32/libclamavd.lib'
        CFLAGS.append('-MDd')
    else:
        LIBFILE = 'contrib/msvc/Release/Win32/libclamav.lib'
        CFLAGS.append('-MD')
    CLINCLUDE = ['/'.join([CLAMAVDEVROOT, 'libclamav'])]
    CLLIB = ['/'.join([CLAMAVDEVROOT, '', LIBFILE])]
else:
    CFLAGS = [ '-Wno-long-long', '-pedantic', '-O0', '-g3' ]
    LIBS = [ 'clamav' ]
    CLINCLUDE = [ '/usr/include' ]
    CLLIB = []

pyc = Extension('pyc',
                sources = ['pyc.c'],
                libraries = LIBS,
                extra_objects = CLLIB,
                extra_link_args = [],
                extra_compile_args = CFLAGS)

# Build : python setup.py build
# Install : python setup.py install
# Register : python setup.py register

setup (name = 'pyc',
       version = '1.0',
       author = 'Gianluigi Tiesi',
       author_email = 'sherpya@netfarm.it',
       license ='GPL',
       keywords="python, clamav, antivirus, scanner, virus, libclamav",
       include_dirs = CLINCLUDE,
       ext_modules = [ pyc ])
