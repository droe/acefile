#!/usr/bin/env python3
# vim: set list et ts=8 sts=4 sw=4 ft=python:

from setuptools import setup, find_packages
import acefile

setup(
    name='acefile',
    version=acefile.__version__,
    description='Read from ACE format archives in pure python',
    long_description=acefile.__doc__,
    url=acefile.__url__,
    author=acefile.__author__,
    author_email=acefile.__email__,
    license=acefile.__license__,
    platforms=['all'],
    classifiers=[
        # https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
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
    entry_points = {
        'console_scripts': [
            'acefile-unace=acefile:unace',
        ],
    },
)

