#!/usr/bin/env python3

import glob
import hashlib
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')
import acefile



def _metadict_from_path(path):
    """
    >>> _metadict_from_path("winappdbg-winappdbg_v1.6.ace")
    {}
    >>> _metadict_from_path("winappdbg-winappdbg_v1.6_password_pw=infected.ace")
    {'pw': 'infected'}
    >>> _metadict_from_path("foo_foo=oof-bar=baz+qux=quux.ace")
    {'foo': 'oof', 'bar': 'baz', 'qux': 'quux'}
    """
    metadict = {}
    for m in re.finditer(r'([a-zA-Z0-9]+)=([^.,;:=+/_-]+)', path):
        metadict[m.group(1)] = m.group(2)
    return metadict



def pytest_generate_tests(metafunc):
    archives = []
    here = os.path.dirname(os.path.abspath(__file__))
    subdirs = ['acefile-testdata']
    if not metafunc.config.getoption("fast"):
        subdirs.append('acefile-testdata-private')
    for subdir in subdirs:
        path = os.path.realpath(f'{here}/../../{subdir}')
        if os.path.exists(path):
            archives += glob.glob(f'{path}/**/*.[aA][cC][eE]', recursive=True)
            archives += glob.glob(f'{path}/**/*.[eE][xX][eE]', recursive=True)
    hashmap = {}
    try:
        for path in archives:
            with open(path, 'rb') as f:
                digest = hashlib.file_digest(f, 'sha256')
            hashmap[digest] = path
        archives = hashmap.values()
    except AttributeError:
        # AttributeError: module 'hashlib' has no attribute 'file_digest'
        # file_digest introduced in Python 3.11, but we still support 3.10.
        # Removal of duplicates is not important in CI/CD testing, so just
        # skip deduplication.
        pass
    metafunc.parametrize("archive_path", archives)



def test_archive_test(archive_path):
    metadict = _metadict_from_path(archive_path)
    pwd = metadict.get('pw', None)
    encoding = metadict.get('encoding', 'utf-8')
    # Disable strict multi-volume for discmaster corpus because we are missing a lot of c00, c01 etc.
    strict_multivolume = metadict.get('strictmultivolume', '/discmaster/' not in archive_path)
    if isinstance(strict_multivolume, str):
        strict_multivolume = strict_multivolume not in ("False", "0", "no")
    assert isinstance(strict_multivolume, bool)
    filenamecontains = metadict.get('filenamecontains', None)
    with acefile.open(archive_path, encoding=encoding, strict_multivolume=strict_multivolume) as f:
        for member in f:
            if member.is_dir():
                continue
            assert f.test(member, pwd=pwd)
            if filenamecontains is not None:
                assert filenamecontains in member.filename



def doctst():
    import doctest
    fails, tests = doctest.testmod(optionflags=doctest.IGNORE_EXCEPTION_DETAIL)
    sys.exit(min(1, fails))



if __name__ == '__main__':
    if '--doctest' in sys.argv:
        doctst()
    raise NotImplementedError("main")
