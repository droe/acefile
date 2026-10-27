#!/usr/bin/env python3

import io
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')
import acefile



def _main_header(flags, tail):
    body = struct.pack('<BH7sBBBBL8s', acefile.Header.TYPE_MAIN, flags,
                       acefile.MainHeader.MAGIC, 20, 20, 2, 0, 0, b'\0' * 8)
    body += tail
    return struct.pack('<HH', acefile.ace_crc16(body), len(body)) + body



@pytest.fixture(autouse=True)
def uncompressed_comments(monkeypatch):
    monkeypatch.setattr(acefile.ACE, 'decompress_comment',
                        staticmethod(lambda value: value))



@pytest.mark.parametrize('slot', [b'', b'\0'])
@pytest.mark.parametrize('size', [0, 1, 2, 255, 256, 257, 512, 4096, 65279])
def test_main_header_comment_layouts(slot, size):
    comment = b'C' * size
    tail = slot + struct.pack('<H', size) + comment
    source = io.BytesIO(_main_header(acefile.Header.FLAG_COMMENT, tail))
    with acefile.open(source, search=0) as archive:
        assert archive.comment == comment.decode('ascii')
        assert archive.advert == ''
        assert list(archive) == []
    assert source.closed



@pytest.mark.parametrize('comment', [b'', b'C', b'comment', b'C' * 256])
@pytest.mark.parametrize('reserved', [b'', b'\0', b'\xaa\xbb', b'R' * 254])
def test_main_header_zero_advert_preserves_reserved_bytes(comment, reserved):
    tail = b'\0' + struct.pack('<H', len(comment)) + comment + reserved
    source = io.BytesIO(_main_header(acefile.Header.FLAG_COMMENT, tail))
    volume = acefile.AceVolume(source, search=0)
    try:
        assert volume.comment == comment.decode('ascii')
        assert volume.advert == ''
        output = io.StringIO()
        volume.dumpheaders(file=output)
        assert 'reserved2   %r' % reserved in output.getvalue()
    finally:
        volume.close()



@pytest.mark.parametrize('comment', [None, b'', b'comment'])
def test_main_header_flagged_advert(comment):
    flags = acefile.Header.FLAG_ADVERT
    tail = b'\x03ACE'
    if comment is not None:
        flags |= acefile.Header.FLAG_COMMENT
        tail += struct.pack('<H', len(comment)) + comment
    with acefile.open(io.BytesIO(_main_header(flags, tail)), search=0) as archive:
        assert archive.advert == 'ACE'
        assert archive.comment == (comment or b'').decode('ascii')



@pytest.mark.parametrize('tail', [b'', b'\0', b'\x03', b'\x03AC'])
def test_main_header_rejects_invalid_flagged_advert(tail):
    source = io.BytesIO(_main_header(acefile.Header.FLAG_ADVERT, tail))
    with pytest.raises(acefile.MainHeaderNotFoundError):
        acefile.open(source, search=0)
    assert source.closed



@pytest.mark.parametrize('tail', [b'\x03ACE\0\0', b'\0', b'\0\x02\0C'])
def test_main_header_rejects_invalid_unflagged_comment(tail):
    source = io.BytesIO(_main_header(acefile.Header.FLAG_COMMENT, tail))
    with pytest.raises(acefile.MainHeaderNotFoundError):
        acefile.open(source, search=0)
    assert source.closed



def test_main_header_zero_advert_without_comment():
    volume = acefile.AceVolume(io.BytesIO(_main_header(0, b'\0')), search=0)
    try:
        assert volume.advert == ''
        assert volume.comment == ''
        output = io.StringIO()
        volume.dumpheaders(file=output)
        assert "reserved2   b''" in output.getvalue()
    finally:
        volume.close()
