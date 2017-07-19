#!/usr/bin/env python3
# vim: set list et ts=8 sts=4 sw=4 ft=python:

from setuptools import setup, find_packages
from setuptools.extension import Extension
import re
import sys
import acefile

if 'sdist' in sys.argv:
    assert re.match(r'[0-9]+\.[0-9]+\.[0-9]+$', acefile.__version__)

title, desc = acefile.__doc__.strip().split('\n', 1)
desc = desc.strip()

def run_setup(with_optional_extensions):
    if with_optional_extensions:
        ext_modules=[Extension(
            "acebitstream", ["c/acebitstream_mod.c", "c/acebitstream.c"],
            define_macros=[(sys.byteorder.upper()+'_ENDIAN_SWAP', 1)]
        )]
    else:
        ext_modules=[]

    setup(
        name='acefile',
        version=acefile.__version__,
        description=title,
        long_description=desc,
        url=acefile.__url__,
        author=acefile.__author__,
        author_email=acefile.__email__,
        license=acefile.__license__,
        platforms=['all'],
        classifiers=[
            # https://pypi.python.org/pypi?%3Aaction=list_classifiers
            'Development Status :: 4 - Beta',
            'License :: OSI Approved :: BSD License',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Topic :: System :: Archiving :: Compression',
        ],
        keywords=['ace', 'unace', 'compression', 'decompression', 'archive'],
        py_modules=['acefile'],
        ext_modules=ext_modules,
        entry_points = {
            'console_scripts': [
                'acefile-unace=acefile:unace',
            ],
        },
    )

try:
    run_setup(True)
except:
    print('=' * 78)
    print('WARNING: The optional C extension(s) could not be compiled!')
    print('Retrying setup without C extension(s) enabled.')
    print('=' * 78)
    run_setup(False)
    print('=' * 78)
    print('WARNING: The optional C extension(s) could not be compiled!')
    print('The module will still be functional, but significantly slower.')
    print('=' * 78)

