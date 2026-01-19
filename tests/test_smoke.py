#!/usr/bin/env python3

import glob
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
    for m in re.finditer(r'([a-zA-Z0-9]+)=([a-zA-Z0-9]+)', path):
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
            archives += glob.glob(f'{path}/**/*.ace')
            archives += glob.glob(f'{path}/**/*.exe')
    metafunc.parametrize("archive_path", archives)



def test_archive_test(archive_path):
    metadict = _metadict_from_path(archive_path)
    pwd = metadict.get('pw', None)
    with acefile.open(archive_path) as f:
        for member in f:
            if member.is_dir():
                continue
            assert f.test(member, pwd=pwd)



def doctst():
    import doctest
    fails, tests = doctest.testmod(optionflags=doctest.IGNORE_EXCEPTION_DETAIL)
    sys.exit(min(1, fails))



if __name__ == '__main__':
    if '--doctest' in sys.argv:
        doctst()
    raise NotImplementedError("main")
