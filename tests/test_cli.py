#!/usr/bin/env python3

import base64
import os
import subprocess
import sys

import pytest


UTF8_NAME_ARCHIVE = (
    'ph0xAAAAECoqQUNFKioUFAIA4QMEXWZUJoQAAAAAFipVTlJFR0lTVEVSRUQgVkVS'
    'U0lPTio/QikAAQEAHQAAAB0AAADaAwRdIAAAALpPoWsAAAAAVEUKAOaXpeacrC50'
    'eHRBQ0UgZmlsZW5hbWUgY29kZS1wYWdlIHRlc3QuCg=='
)



@pytest.mark.skipif(os.name != 'nt', reason='Windows stream behavior')
@pytest.mark.parametrize('verbose', [False, True])
def test_cli_lists_unicode_filename_as_utf8(tmp_path, verbose):
    archive_path = tmp_path / '日本.ace'
    archive_path.write_bytes(base64.b64decode(UTF8_NAME_ARCHIVE))
    acefile_path = os.path.join(os.path.dirname(__file__), '..', 'acefile.py')
    environment = os.environ.copy()
    environment['PYTHONIOENCODING'] = 'cp1252'
    command = [sys.executable, acefile_path, '--list', '--batch', str(archive_path)]
    if verbose:
        command.append('--verbose')
    result = subprocess.run(command, capture_output=True, env=environment)

    assert result.returncode == 0
    if verbose:
        assert result.stdout.decode('utf-8').splitlines()[0].endswith('  日本.txt')
        assert 'processing archive %s' % archive_path in result.stderr.decode('utf-8')
    else:
        assert result.stdout.decode('utf-8').splitlines() == ['日本.txt']
        assert result.stderr == b''



def test_library_import_preserves_stream_encodings():
    environment = os.environ.copy()
    environment['PYTHONIOENCODING'] = 'cp1252'
    repository = os.path.join(os.path.dirname(__file__), '..')
    result = subprocess.run(
        [sys.executable, '-c',
         'import acefile, sys; print(sys.stdout.encoding); print(sys.stderr.encoding)'],
        cwd=repository, capture_output=True, env=environment)

    assert result.returncode == 0
    assert result.stdout.splitlines() == [b'cp1252', b'cp1252']
    assert result.stderr == b''
