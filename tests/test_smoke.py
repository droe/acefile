#!/usr/bin/env python3

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')
import acefile



def pytest_generate_tests(metafunc):
    archives = []
    here = os.path.dirname(os.path.abspath(__file__))
    for tldir in ('acefile-testdata', 'acefile-testdata-private'):
        path = os.path.realpath(f'{here}/../../{tldir}')
        if os.path.exists(path):
            archives += glob.glob(f'{path}/**/*.ace')
            archives += glob.glob(f'{path}/**/*.exe')
    # TODO parse pw= and pass as password to test functions
    archives = [a for a in archives if 'pw=' not in a]
    metafunc.parametrize("archive_path", archives)



def test_archive_test(archive_path):
    with acefile.open(archive_path) as f:
        for member in f:
            if member.is_dir():
                continue
            assert f.test(member)
