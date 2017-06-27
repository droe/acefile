#!/usr/bin/env python3
# vim: set list et ts=8 sts=4 sw=4 ft=python:

# acefile - read from ACE format archives in pure python
# Copyright (C) 2017, Daniel Roethlisberger <daniel@roe.ch>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions, and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# NOTE:  The ACE archive format and ACE compression and decompression
# algorithms have been designed by Marcel Lemke.  The above copyright
# notice and license does not constitute a claim of intellectual property
# over ACE technology beyond the copyright of this python implementation.

"""
Read from ACE format archives in pure python.

This single-file, pure-python, no-dependencies python 3 implementation is
designed to be used both as a library and as a stand-alone unace utility.
The library API is modeled after tarfile.  As pure-python implementation,
it is significantly slower than native implementations.

This implementation supports up to version 2.0 of the ACE archive format,
including the EXE, DIFF, PIC and SOUND modes of ACE 2.0 and including
password protected archives.

This is an implementation from scratch, based on the 1998 document titled
"Technical information of the archiver ACE v1.2" by Marcel Lemke, using
unace 2.5 and WinAce 2.69 by Marcel Lemke as reference implementations.
"""

__version__     = '0.4.3'
__author__      = 'Daniel Roethlisberger'
__email__       = 'daniel@roe.ch'
__copyright__   = 'Copyright 2017, Daniel Roethlisberger'
__credits__     = ['Marcel Lemke']
__license__     = 'BSD'
__url__         = 'https://www.roe.ch/acefile'

__all__         = ['AceFile', 'AceInfo', 'is_acefile', 'AceError']

# TODO
# -   Multivolume support

import array
import datetime
import io
import math
import os
import struct
import sys



def eprint(*args, **kwargs):
    """
    Print to stderr.
    """
    print(*args, file=sys.stderr, **kwargs)



# haklib.dt
def _dt_fromdos(dosdt):
    """
    Convert DOS format 32bit timestamp to datetime object.
    Timestamps with illegal values out of the allowed range are ignored and a
    datetime object representing 1980-01-01 00:00:00 is returned instead.
    https://msdn.microsoft.com/en-us/library/9kkf9tah.aspx
    """
    try:
        return datetime.datetime(
                ((dosdt >> 25) & 0x7F) + 1980,
                 (dosdt >> 21) & 0x0F,
                 (dosdt >> 16) & 0x1F,
                 (dosdt >> 11) & 0x1F,
                 (dosdt >>  5) & 0x3F,
                ((dosdt      ) & 0x1F) * 2)
    except ValueError:
        return datetime.datetime(1980, 1, 1, 0, 0, 0)



# haklib.c
def c_div(q, d):
    """
    Arbitrary signed integer division with c behaviour.
    """
    s = int(math.copysign(1, q) * math.copysign(1, d))
    return s * int(abs(q) / abs(d))

def c_uchar(i):
    """
    Convert arbitrary integer to c unsigned char type range as if casted in c.
    """
    return i & 0xFF

def c_rot32(i, n):
    """
    Rotate *i* left by *n* bits within the uint32 value range.
    """
    return ((i << n) | (i >> (32 - n)))

def c_add32(a, b):
    """
    Add *a* and *b* within the uint32 value range.
    """
    return (a + b) & 0xFFFFFFFF

def c_sum32(*args):
    """
    Add all elements of *args* within the uint32 value range.
    """
    return sum(args) & 0xFFFFFFFF



def asciibox(msg, title=None, minwidth=None):
    """
    Returns message string *msg* wrapped in a plain ASCII box.
    If *width* is given, pad the lines to *width* characters.
    If *title* is given, add *title* in the top horizontal bar.
    """
    out = []
    lines = msg.splitlines()
    width = 0
    for line in lines:
        width = max(width, len(line))
    if minwidth != None:
        width = max(width, minwidth)
    if title != None:
        width = max(width, len(title) + 6)
    ftr = "+" + ("-" * (width + 2)) + "+"
    if title != None:
        hdr = ("+--[ %s ]--" % title) + ("-" * (width - 6 - len(title))) + "+"
    else:
        hdr = ftr
    fmt = "| %%-%is |" % width
    out.append(hdr)
    for line in msg.splitlines():
        out.append(fmt % line)
    out.append(ftr)
    return '\n'.join(out)



# arbitrarily chosen buffer size to use for file operations
FILE_BLOCKSIZE = 131072
assert FILE_BLOCKSIZE % 4 == 0



def classinit_crctab(cls):
    """
    Decorator that calculates a CRC table and stores it in the class.
    This ensures that the table is calculated exactly once.
    """
    cls._crctab = []
    for i in range(256):
        hval = i
        for j in range(8):
            if hval & 1:
                hval = (hval >> 1) ^ 0xEDB88320
            else:
                hval >>= 1
        cls._crctab.append(hval)
    return cls

@classinit_crctab
class AceCRC32:
    """
    Calculate an ACE CRC-32 checksum.

    Even though ACE CRC-32 uses the standard CRC-32 polynomial in reversed
    notation, the algorithm produces different results than standard CRC-32 as
    used by PKZIP and other formats.
    """

    def __init__(self, buf=b''):
        """
        Initialize and add bytes in *buf* into checksum.
        """
        self.crc32 = 0xFFFFFFFF
        if len(buf) > 0:
            self += buf

    def __iadd__(self, buf):
        """
        Adding a buffer of bytes into the checksum, updating the rolling
        checksum from all previously added buffers.
        """
        crc32 = self.crc32
        for c in buf:
            crc32 = self._crctab[(crc32 ^ c) & 0xFF] ^ (crc32 >> 8)
        self.crc32 = crc32
        return self

    def __eq__(self, other):
        """
        Compare the checksum to a fixed value or another ACE CRC32 object.
        """
        return self.sum == other

    def __format__(self, format_spec):
        """
        Format the checksum for printing.
        """
        return self.sum.__format__(format_spec)

    @property
    def sum(self):
        """
        The checksum.
        """
        return self.crc32

class AceCRC16(AceCRC32):
    """
    Calculate an ACE CRC-16 checksum, which is actually just the lower 16 bits
    of an ACE CRC-32.
    """
    @property
    def sum(self):
        """
        The checksum.
        """
        return self.crc32 & 0xFFFF

def ace_crc32(buf):
    """
    Return the ACE CRC-32 checksum of the bytes in *buf*.
    """
    return AceCRC32(buf).sum

def ace_crc16(buf):
    """
    Return the ACE CRC-16 checksum of the bytes in *buf*.
    """
    return AceCRC16(buf).sum



class BitStream:
    """
    Intel-endian 32bit-byte-swapped, MSB first bitstream, reading
    from a file-like object.
    """
    class Depleted(Exception):
        """
        Raised when an attempt is made to read beyond the available data.
        """
        pass

    @staticmethod
    def _getbits(value, start, length):
        """
        Return *length* bits from byte *value*, starting at position *start*.
        Behaviour is undefined for start < 0, length < 0 or start + length > 32.
        """
        #assert start >= 0 and length >= 0 and start + length <= 32
        mask = ((0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF) >> start
        return (value & mask) >> (32 - length - start)

    def __init__(self, f, size):
        """
        Initialize BitStream reading from file-like object *f* a maximum of
        *size* bytes, after which there is a maximum of 32 bits zero padding.
        """
        assert size % 4 == 0
        self.__file = f
        self.__file_remaining = size    # in bytes
        self.__buf = array.array('I')
        self.__len = 0                  # in bits
        self.__pos = 0                  # in bits
        self._refill()

    def _refill(self):
        """
        Refill the internal buffer with data read from file.
        """
        if self.__file_remaining == 0:
            raise self.Depleted()

        amount = min(self.__file_remaining, FILE_BLOCKSIZE)
        tmpbuf = self.__file.read(amount)
        if len(tmpbuf) < amount:
            raise self.Depleted()
        self.__file_remaining -= len(tmpbuf)

        newbuf = self.__buf[-1:]
        for i in range(0, len(tmpbuf), 4):
            newbuf.append(struct.unpack('<L', tmpbuf[i:i+4])[0])
        if len(tmpbuf) < FILE_BLOCKSIZE:
            newbuf.append(0)
        if self.__pos > 0:
            self.__pos -= (self.__len - 32)
        self.__buf = newbuf
        self.__len = 32 * len(newbuf)

    def _have_bits(self, bits):
        """
        Ensure we have *bits* bits available in internal buffer by refilling
        if necessary.
        """
        if self.__pos + bits > self.__len:
            self._refill()

    def skip_bits(self, bits):
        """
        Skip *bits* bits in the stream.
        """
        self._have_bits(bits)
        self.__pos += bits

    def peek_bits(self, bits):
        """
        Peek at next *bits* bits in the stream without incrementing position.
        """
        self._have_bits(bits)
        peeked = min(bits, 32 - (self.__pos % 32))
        res = self._getbits(self.__buf[self.__pos // 32],
                            self.__pos % 32, peeked)
        while bits - peeked >= 32:
            res <<= 32
            res += self.__buf[(self.__pos + peeked) // 32]
            peeked += 32
        if bits - peeked > 0:
            res <<= bits - peeked
            res += self._getbits(self.__buf[(self.__pos + peeked) // 32],
                                 0, bits - peeked)
        return res

    def read_bits(self, bits):
        """
        Read *bits* bits from bitstream and increment position accordingly.
        """
        value = self.peek_bits(bits)
        self.skip_bits(bits)
        return value

    def golomb_rice(self, r_bits, signed=False):
        """
        Read a Golomb-Rice code with *r_bits* remainder bits and an arbitrary
        number of quotient bits from bitstream and return the represented
        value.  Iff *signed* is True, interpret the lowest order bit as sign
        bit and return a signed integer.
        """
        if r_bits == 0:
            value = 0
        else:
            assert r_bits > 0
            value = self.read_bits(r_bits)
        while self.read_bits(1) == 1:
            value += 1 << r_bits
        if signed == False:
            return value
        if value & 1:
            return - (value >> 1) - 1
        else:
            return value >> 1



class EncryptedFileIO:
    """
    Non-seekable file-like object that reads from a lower-level file-like
    object and transparently decrypts the data stream.
    """

    SHA1_A = 0x67452301
    SHA1_B = 0xefcdab89
    SHA1_C = 0x98badcfe
    SHA1_D = 0x10325476
    SHA1_E = 0xc3d2e1f0

    BF_P = (
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
        0x9216D5D9, 0x8979FB1B)

    BF_S0 = (
        0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7,
        0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
        0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
        0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E,
        0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE,
        0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013,
        0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF,
        0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E,
        0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
        0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440,
        0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE,
        0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A,
        0x2DA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87901E,
        0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677,
        0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
        0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032,
        0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88,
        0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
        0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E,
        0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0,
        0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
        0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98,
        0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88,
        0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
        0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6,
        0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D,
        0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
        0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7,
        0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA,
        0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463,
        0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F,
        0x6DFC511F, 0x9B30952C, 0xCC814544, 0xAF5EBD09,
        0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3,
        0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB,
        0x5579C0BD, 0x1A60320A, 0xD6A100C6, 0x412C7279,
        0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
        0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB,
        0x323DB5FA, 0xFD238760, 0x53317B48, 0x3E00DF82,
        0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB,
        0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573,
        0x695B27B0, 0xBBCA58C8, 0xE1FFA35D, 0xB8F011A0,
        0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B,
        0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790,
        0xE1DDF2DA, 0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8,
        0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
        0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0,
        0xD08ED1D0, 0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7,
        0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C,
        0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD,
        0x2F2F2218, 0xBE0E1777, 0xEA752DFE, 0x8B021FA1,
        0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299,
        0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9,
        0x165FA266, 0x80957705, 0x93CC7314, 0x211A1477,
        0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF,
        0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49,
        0x00250E2D, 0x2071B35E, 0x226800BB, 0x57B8E0AF,
        0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA,
        0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5,
        0x83260376, 0x6295CFA9, 0x11C81968, 0x4E734A41,
        0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915,
        0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400,
        0x08BA6FB5, 0x571BE91F, 0xF296EC6B, 0x2A0DD915,
        0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664,
        0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A)

    BF_S1 = (
        0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623,
        0xAD6EA6B0, 0x49A7DF7D, 0x9CEE60B8, 0x8FEDB266,
        0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1,
        0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E,
        0x3F54989A, 0x5B429D65, 0x6B8FE4D6, 0x99F73FD6,
        0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1,
        0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E,
        0x09686B3F, 0x3EBAEFC9, 0x3C971814, 0x6B6A70A1,
        0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737,
        0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8,
        0xB03ADA37, 0xF0500C0D, 0xF01C1F04, 0x0200B3FF,
        0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD,
        0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701,
        0x3AE5E581, 0x37C2DADC, 0xC8B57634, 0x9AF3DDA7,
        0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41,
        0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331,
        0x4E548B38, 0x4F6DB908, 0x6F420D03, 0xF60A04BF,
        0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF,
        0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E,
        0x5512721F, 0x2E6B7124, 0x501ADDE6, 0x9F84CD87,
        0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C,
        0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2,
        0xEF1C1847, 0x3215D908, 0xDD433B37, 0x24C2BA16,
        0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD,
        0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B,
        0x043556F1, 0xD7A3C76B, 0x3C11183B, 0x5924A509,
        0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E,
        0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3,
        0x771FE71C, 0x4E3D06FA, 0x2965DCB9, 0x99E71D0F,
        0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A,
        0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4,
        0xF2F74EA7, 0x361D2B3D, 0x1939260F, 0x19C27960,
        0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66,
        0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28,
        0xC332DDEF, 0xBE6C5AA5, 0x65582185, 0x68AB9802,
        0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84,
        0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510,
        0x13CCA830, 0xEB61BD96, 0x0334FE1E, 0xAA0363CF,
        0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14,
        0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E,
        0x648B1EAF, 0x19BDF0CA, 0xA02369B9, 0x655ABB50,
        0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7,
        0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8,
        0xF837889A, 0x97E32D77, 0x11ED935F, 0x16681281,
        0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99,
        0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696,
        0xCDB30AEB, 0x532E3054, 0x8FD948E4, 0x6DBC3128,
        0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73,
        0x5D4A14D9, 0xE864B7E3, 0x42105D14, 0x203E13E0,
        0x45EEE2B6, 0xA3AAABEA, 0xDB6C4F15, 0xFACB4FD0,
        0xC742F442, 0xEF6ABBB5, 0x654F3B1D, 0x41CD2105,
        0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250,
        0xCF62A1F2, 0x5B8D2646, 0xFC8883A0, 0xC1C7B6A3,
        0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285,
        0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00,
        0x58428D2A, 0x0C55F5EA, 0x1DADF43E, 0x233F7061,
        0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB,
        0x7CDE3759, 0xCBEE7460, 0x4085F2A7, 0xCE77326E,
        0xA6078084, 0x19F8509E, 0xE8EFD855, 0x61D99735,
        0xA969A7AA, 0xC50C06C2, 0x5A04ABFC, 0x800BCADC,
        0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9,
        0xDB73DBD3, 0x105588CD, 0x675FDA79, 0xE3674340,
        0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20,
        0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7)

    BF_S2 = (
        0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934,
        0x411520F7, 0x7602D4F7, 0xBCF46B2E, 0xD4A20068,
        0xD4082471, 0x3320F46A, 0x43B7D4B7, 0x500061AF,
        0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840,
        0x4D95FC1D, 0x96B591AF, 0x70F4DDD3, 0x66A02F45,
        0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504,
        0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A,
        0x28507825, 0x530429F4, 0x0A2C86DA, 0xE9B66DFB,
        0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE,
        0x4F3FFEA2, 0xE887AD8C, 0xB58CE006, 0x7AF4D6B6,
        0xAACE1E7C, 0xD3375FEC, 0xCE78A399, 0x406B2A42,
        0x20FE9E35, 0xD9F385B9, 0xEE39D7AB, 0x3B124E8B,
        0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2,
        0x3A6EFA74, 0xDD5B4332, 0x6841E7F7, 0xCA7820FB,
        0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527,
        0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B,
        0x55A867BC, 0xA1159A58, 0xCCA92963, 0x99E1DB33,
        0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C,
        0xFDF8E802, 0x04272F70, 0x80BB155C, 0x05282CE3,
        0x95C11548, 0xE4C66D22, 0x48C1133F, 0xC70F86DC,
        0x07F9C9EE, 0x41041F0F, 0x404779A4, 0x5D886E17,
        0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564,
        0x257B7834, 0x602A9C60, 0xDFF8E8A3, 0x1F636C1B,
        0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115,
        0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922,
        0x85B2A20E, 0xE6BA0D99, 0xDE720C8C, 0x2DA2F728,
        0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0,
        0x5449A36F, 0x877D48FA, 0xC39DFD27, 0xF33E8D1E,
        0x0A476341, 0x992EFF74, 0x3A6F6EAB, 0xF4F8FD37,
        0xA812DC60, 0xA1EBDDF8, 0x991BE14C, 0xDB6E6B0D,
        0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804,
        0xF1290DC7, 0xCC00FFA3, 0xB5390F92, 0x690FED0B,
        0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3,
        0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB,
        0x37392EB3, 0xCC115979, 0x8026E297, 0xF42E312D,
        0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C,
        0x6A124237, 0xB79251E7, 0x06A1BBE6, 0x4BFB6350,
        0x1A6B1018, 0x11CAEDFA, 0x3D25BDD8, 0xE2E1C3C9,
        0x44421659, 0x0A121386, 0xD90CEC6E, 0xD5ABEA2A,
        0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE,
        0x9DBC8057, 0xF0F7C086, 0x60787BF8, 0x6003604D,
        0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC,
        0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F,
        0x77A057BE, 0xBDE8AE24, 0x55464299, 0xBF582E61,
        0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2,
        0x5366F9C3, 0xC8B38E74, 0xB475F255, 0x46FCD9B9,
        0x7AEB2661, 0x8B1DDF84, 0x846A0E79, 0x915F95E2,
        0x466E598E, 0x20B45770, 0x8CD55591, 0xC902DE4C,
        0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E,
        0xB77F19B6, 0xE0A9DC09, 0x662D09A1, 0xC4324633,
        0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10,
        0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169,
        0xDCB7DA83, 0x573906FE, 0xA1E2CE9B, 0x4FCD7F52,
        0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027,
        0x9AF88C27, 0x773F8641, 0xC3604C06, 0x61A806B5,
        0xF0177A28, 0xC0F586E0, 0x006058AA, 0x30DC7D62,
        0x11E69ED7, 0x2338EA63, 0x53C2DD94, 0xC2C21634,
        0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76,
        0x6F05E409, 0x4B7C0188, 0x39720A3D, 0x7C927C24,
        0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC,
        0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4,
        0x1E50EF5E, 0xB161E6F8, 0xA28514D9, 0x6C51133C,
        0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837,
        0xD79A3234, 0x92638212, 0x670EFA8E, 0x406000E0)

    BF_S3 = (
        0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B,
        0x5CB0679E, 0x4FA33742, 0xD3822740, 0x99BC9BBE,
        0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B,
        0xB78C1B6B, 0x21A19045, 0xB26EB1BE, 0x6A366EB4,
        0x5748AB2F, 0xBC946E79, 0xC6A376D2, 0x6549C2C8,
        0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6,
        0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304,
        0xA1FAD5F0, 0x6A2D519A, 0x63EF8CE2, 0x9A86EE22,
        0xC089C2B8, 0x43242EF6, 0xA51E03AA, 0x9CF2D0A4,
        0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6,
        0x2826A2F9, 0xA73A3AE1, 0x4BA99586, 0xEF5562E9,
        0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59,
        0x80E4A915, 0x87B08601, 0x9B09E6AD, 0x3B3EE593,
        0xE990FD5A, 0x9E34D797, 0x2CF0B7D9, 0x022B8B51,
        0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28,
        0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C,
        0xE029AC71, 0xE019A5E6, 0x47B0ACFD, 0xED93FA9B,
        0xE8D3C48D, 0x283B57CC, 0xF8D56629, 0x79132E28,
        0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C,
        0x15056DD4, 0x88F46DBA, 0x03A16125, 0x0564F0BD,
        0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A,
        0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB, 0x26DCF319,
        0x7533D928, 0xB155FDF5, 0x03563482, 0x8ABA3CBB,
        0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F,
        0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991,
        0xEA7A90C2, 0xFB3E7BCE, 0x5121CE64, 0x774FBE32,
        0xA8B6E37E, 0xC3293D46, 0x48DE5369, 0x6413E680,
        0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166,
        0xB39A460A, 0x6445C0DD, 0x586CDECF, 0x1C20C8AE,
        0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB,
        0xDDA26A7E, 0x3A59FF45, 0x3E350A44, 0xBCB4CDD5,
        0x72EACEA8, 0xFA6484BB, 0x8D6612AE, 0xBF3C6F47,
        0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370,
        0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D,
        0x4040CB08, 0x4EB4E2CC, 0x34D2466A, 0x0115AF84,
        0xE1B00428, 0x95983A1D, 0x06B89FB4, 0xCE6EA048,
        0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8,
        0x611560B1, 0xE7933FDC, 0xBB3A792B, 0x344525BD,
        0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9,
        0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3, 0xA1E8AAC7,
        0x1A908749, 0xD44FBD9A, 0xD0DADECB, 0xD50ADA38,
        0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F,
        0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C,
        0xBF97222C, 0x15E6FC2A, 0x0F91FC71, 0x9B941525,
        0xFAE59361, 0xCEB69CEB, 0xC2A86459, 0x12BAA8D1,
        0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442,
        0xE0EC6E0E, 0x1698DB3B, 0x4C98A0BE, 0x3278E964,
        0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E,
        0x1B0A7441, 0x4BA3348C, 0xC5BE7120, 0xC37632D8,
        0xDF359F8D, 0x9B992F2E, 0xE60B6F47, 0x0FE3F11D,
        0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F,
        0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299,
        0xF523F357, 0xA6327623, 0x93A83531, 0x56CCCD02,
        0xACF08162, 0x5A75EBB5, 0x6E163697, 0x88D273CC,
        0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614,
        0xE6C6C7BD, 0x327A140A, 0x45E1D006, 0xC3F27B9A,
        0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6,
        0x71126905, 0xB2040222, 0xB6CBCF7C, 0xCD769C2B,
        0x53113EC0, 0x1640E3D3, 0x38ABBD60, 0x2547ADF0,
        0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060,
        0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E,
        0x1948C25C, 0x02FB8A8C, 0x01C36AE4, 0xD6EBE1F9,
        0x90D4F869, 0xA65CDEA0, 0x3F09252D, 0xC208E69F,
        0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6)

    def __init__(self, f, pwd):
        """
        Wrap file-like object *f*, decrypting using password *pwd*, which can
        be str or bytes.  File-like object *f* is expected to be at the correct
        position; this class will only use the read() method on *f*.
        """
        if isinstance(pwd, str):
            pwd = pwd.encode('utf-8')
        self.__file = f
        self._bf_init(self._derive_key(pwd))
        self.__buffer = b''

    def _bf_init(self, key):
        """
        Initialize blowfish state using 160-bit key *key* as list or tuple of
        integers.
        """
        self.__p = [self.BF_P[i] ^ key[i % len(key)] \
                for i in list(range(len(self.BF_P)))]
        self.__s = (list(self.BF_S0), list(self.BF_S1),
                    list(self.BF_S2), list(self.BF_S3))
        self.__lastcl = 0
        self.__lastcr = 0
        l = r = 0
        for i in range(0, 18, 2):
            l, r = self._bf_encrypt_block(l, r)
            self.__p[i] = l
            self.__p[i + 1] = r
        for i in range(0, 4):
            for j in range(0, 256, 2):
                l, r = self._bf_encrypt_block(l, r)
                self.__s[i][j] = l
                self.__s[i][j + 1] = r

    def _bf_func(self, x):
        """
        The blowfish round function operating on an integer.
        """
        h = c_add32(self.__s[0][x >> 24], self.__s[1][x >> 16 & 0xff])
        return c_add32((h ^ self.__s[2][x >> 8 & 0xff]), self.__s[3][x & 0xff])

    def _bf_encrypt_block(self, l, r):
        """
        Encrypt a single block consisting of integers *l* and *r*.
        """
        for i in range(0, 16, 2):
            l ^= self.__p[i]
            r ^= self._bf_func(l)
            r ^= self.__p[i+1]
            l ^= self._bf_func(r)
        l ^= self.__p[16]
        r ^= self.__p[17]
        return (r, l)

    def _bf_decrypt_block(self, l, r):
        """
        Decrypt a single block consisting of integers *l* and *r*.
        """
        for i in range(16, 0, -2):
            l ^= self.__p[i+1]
            r ^= self._bf_func(l)
            r ^= self.__p[i]
            l ^= self._bf_func(r)
        l ^= self.__p[1]
        r ^= self.__p[0]
        return (r, l)

    def _bf_cbc_decrypt(self, buf):
        """
        Decrypt a buffer in CBC mode with an IV of all zeroes.
        """
        assert len(buf) % 8 == 0
        out = []
        for i in range(0, len(buf), 8):
            cl, cr = struct.unpack('<LL', buf[i:i+8])
            pl, pr = self._bf_decrypt_block(cl, cr)
            pl ^= self.__lastcl
            pr ^= self.__lastcr
            self.__lastcl = cl
            self.__lastcr = cr
            out.append(struct.pack('<LL', pl, pr))
        return b''.join(out)

    def _derive_key(self, pwd):
        """
        Derive the decryption key from password bytes *pwd* using a single
        application of SHA-1 using non-standard padding.
        """
        buf = pwd + bytes([0x80] + [0] * (64 - len(pwd) - 5))
        state = []
        state.extend(struct.unpack('<15L', buf))
        state.append(len(pwd) << 3)
        assert len(state) == 16
        for i in range(len(state), 80):
            state.append(state[i-16] ^ state[i-14] ^ state[i-8] ^ state[i-3])
        assert len(state) == 80
        a = self.SHA1_A
        b = self.SHA1_B
        c = self.SHA1_C
        d = self.SHA1_D
        e = self.SHA1_E
        for i in range(20):
            a, b, c, d, e = \
                c_sum32(c_rot32(a, 5), ((b&c)|(~b&d)), e, state[i],
                        0x5a827999), a, c_rot32(b, 30), c, d
        for i in range(20, 40):
            a, b, c, d, e = \
                c_sum32(c_rot32(a, 5), (b^c^d), e, state[i],
                        0x6ed9eba1), a, c_rot32(b, 30), c, d
        for i in range(40, 60):
            a, b, c, d, e = \
                c_sum32(c_rot32(a, 5), ((b&c)|(b&d)|(c&d)), e, state[i],
                        0x8f1bbcdc), a, c_rot32(b, 30), c, d
        for i in range(60, 80):
            a, b, c, d, e = \
                c_sum32(c_rot32(a, 5), (b^c^d), e, state[i],
                        0xca62c1d6), a, c_rot32(b, 30), c, d
        a = c_add32(a, self.SHA1_A)
        b = c_add32(b, self.SHA1_B)
        c = c_add32(c, self.SHA1_C)
        d = c_add32(d, self.SHA1_D)
        e = c_add32(e, self.SHA1_E)
        return (a, b, c, d, e)

    def seekable():
        return False

    def read(self, n):
        """
        Read *n* bytes from the decrypted file.
        """
        if n < len(self.__buffer):
            rbuf = self.__buffer[:n]
            self.__buffer = self.__buffer[n:]
            return rbuf
        want_bytes = n - len(self.__buffer)
        read_bytes = want_bytes
        if want_bytes & 0x7:
            read_bytes += 8 - (want_bytes & 0x7)
        buf = self.__file.read(read_bytes)
        buf = self._bf_cbc_decrypt(buf)
        rbuf = self.__buffer + buf[:n]
        self.__buffer = buf[n:]
        return rbuf



class Huffman:
    """
    Huffman decoder engine.  All methods are static.
    """
    MAXWIDTHSVDWD       = 7
    MAXWIDTHTOSAVE      = 15

    @staticmethod
    def _quicksort(keys, values, count):
        """
        In-place quicksort implementation yielding the correct order even
        between the symbols that have identical frequencies.
        """
        def _quicksort_subrange(left, right):
            def _list_swap(_list, a, b):
                _list[a], _list[b] = _list[b], _list[a]

            new_left = left
            new_right = right
            m = keys[right]
            while True:
                while keys[new_left] > m:
                    new_left += 1
                while keys[new_right] < m:
                    new_right -= 1
                if new_left <= new_right:
                    _list_swap(keys,   new_left, new_right)
                    _list_swap(values, new_left, new_right)
                    new_left += 1
                    new_right -= 1
                if new_left >= new_right:
                    break
            if left < new_right:
                if left < new_right - 1:
                    _quicksort_subrange(left, new_right)
                else:
                    if keys[left] < keys[new_right]:
                        _list_swap(keys,   left, new_right)
                        _list_swap(values, left, new_right)
            if right > new_left:
                if new_left < right - 1:
                    _quicksort_subrange(new_left, right)
                else:
                    if keys[new_left] < keys[right]:
                        _list_swap(keys,   new_left, right)
                        _list_swap(values, new_left, right)

        _quicksort_subrange(0, count - 1)

    @staticmethod
    def _make_codes(max_width, count, widths, codes):
        frequencies = list(widths)
        elements    = list(range(len(widths)))

        Huffman._quicksort(frequencies, elements, count)

        actual_size = 0
        while actual_size < len(frequencies) and frequencies[actual_size] != 0:
            actual_size += 1

        if actual_size < 2:
            widths[elements[0]] = 1
            if actual_size == 0:
                actual_size += 1

        actual_size -= 1
        max_code_pos = 1 << max_width
        code_pos = 0
        i = actual_size
        while i >= 0 and code_pos < max_code_pos:
            if max_width - frequencies[i] < 0:
                raise CorruptedArchiveError("max_width - frequencies[i] < 0")
            num_codes = 1 << (max_width - frequencies[i])
            code = elements[i]
            if code_pos + num_codes > max_code_pos:
                raise CorruptedArchiveError("code_pos+num_codes>max_code_pos")
            for j in range(code_pos, code_pos + num_codes):
                codes[j] = code
            code_pos += num_codes
            i -= 1

    @staticmethod
    def read_widths(bs, max_width, num_codes):
        """
        Read Huffman codes and their widths from BitStream *bs*.
        The caller specifies the maximum width of a single code *max_width*
        and the number of codes *num_codes*.
        """
        codes = [0] * (1 << max_width)
        widths = [0] * (num_codes + 1)

        num_widths = bs.read_bits(9) + 1
        if num_widths > num_codes + 1:
            num_widths = num_codes + 1
        lower_width = bs.read_bits(4)
        upper_width = bs.read_bits(4)

        save_widths = [0] * (Huffman.MAXWIDTHTOSAVE + 1)
        for i in range(upper_width + 1):
            save_widths[i] = bs.read_bits(3)
        Huffman._make_codes(Huffman.MAXWIDTHSVDWD,
                            upper_width + 1,
                            save_widths,
                            codes)

        width_pos = 0
        while width_pos < num_widths:
            code = codes[bs.peek_bits(Huffman.MAXWIDTHSVDWD)]
            bs.skip_bits(save_widths[code])

            if code < upper_width:
                widths[width_pos] = code
                width_pos += 1
            else:
                length = bs.read_bits(4) + 4
                while length > 0 and width_pos < num_widths:
                    widths[width_pos] = 0
                    width_pos += 1
                    length -= 1

        if upper_width > 0:
            for i in range(1, num_widths):
                widths[i] = (widths[i] + widths[i - 1]) % upper_width

        for i in range(num_widths):
            if widths[i] > 0:
                widths[i] += lower_width

        Huffman._make_codes(max_width, num_widths, widths, codes)
        return (codes, widths)



class LZ77:
    """
    ACE 1.0 and ACE 2.0 LZ77 mode decompression engine.
    """

    class SymbolStream:
        """
        Stream of LZ77 symbols and their arguments.
        """
        def __init__(self):
            self.__tuples = []
            self.__current_tuple = None

        def append(self, symbol, arg1=None, arg2=None):
            self.__tuples.append((symbol, arg1, arg2))

        def __len__(self):
            return len(self.__tuples)

        def __iter__(self):
            return self

        def __next__(self):
            if len(self.__tuples) == 0:
                raise StopIteration()
            self.__current_tuple = self.__tuples.pop(0)
            return self

        @property
        def symbol(self):
            return self.__current_tuple[0]

        @property
        def args(self):
            return self.__current_tuple[1:]

        @property
        def len(self):
            return self.__current_tuple[1]

        @property
        def dist(self):
            return self.__current_tuple[2]

        @property
        def typecode(self):
            return self.__current_tuple[1]

        @property
        def typeargs(self):
            return self.__current_tuple[2]

        @property
        def next_symbol(self):
            if len(self.__tuples) == 0:
                return None
            return self.__tuples[0][0]


    class DistHist:
        """
        Distance value cache for storing the last SIZE used LZ77 distances.
        """
        SIZE = 4

        def __init__(self):
            self.__hist = [0] * self.SIZE

        def append(self, dist):
            self.__hist.pop(0)
            self.__hist.append(dist)

        def retrieve(self, offset):
            assert offset >= 0 and offset < self.SIZE
            dist = self.__hist.pop(self.SIZE - offset - 1)
            self.__hist.append(dist)
            return dist


    #   0..255  character literals
    # 256..259  copy from dictionary, dist from dist history -1..-4
    # 260..282  copy from dictionary, dist 0..22 bits from bitstream
    # 283       type code
    MAXCODEWIDTH        = 11
    MAXLEN              = 259
    MAXDISTATLEN2       = 255
    MAXDISTATLEN3       = 8191
    MINDICBITS          = 10
    MAXDICBITS          = 22
    MAXDICBITS2         = MAXDICBITS >> 1
    MAXDICSIZE          = 1 << MAXDICBITS
    MAXDIST2            = 1 << MAXDICBITS2
    TYPECODE            = 260 + MAXDICBITS + 1
    NUMMAINCODES        = 260 + MAXDICBITS + 2
    NUMLENCODES         = 256 - 1

    def __init__(self):
        self.__dictionary = []
        self.__dicsize = 1 << LZ77.MINDICBITS

    def reinit(self):
        """
        Reinitialize the LZ77 decompression engine.
        Reset all data dependent state to initial values.
        """
        self.__symbols = LZ77.SymbolStream()
        self.__disthist = LZ77.DistHist()
        self.__leftover = []

    def set_dicbits(self, dicbits):
        """
        Set the dicbits parameter, indicating minimum required dictionary size.
        """
        self.__dicsize = min(max(1 << dicbits, self.__dicsize), LZ77.MAXDICSIZE)

    def dic_copy(self, buf):
        """
        Copy buf to LZ77 dictionary and truncate dictionary.
        Used by other compression modes to register their output into the
        LZ77 dictionary.
        """
        self.__dictionary.extend(buf)
        self._dic_truncate()

    def _dic_truncate(self):
        """
        Truncate the internal dictionary to the minimum required dictionary
        size in order to save memory.  This is actually a super slow operation
        that adds considerably to runtime.
        """
        self.__dictionary = self.__dictionary[-self.__dicsize:]

    # quasi-static
    def _read_tabs(self, bs):
        main_syms, main_widths = Huffman.read_widths(bs,
                                                     LZ77.MAXCODEWIDTH,
                                                     LZ77.NUMMAINCODES)
        len_syms,  len_widths  = Huffman.read_widths(bs,
                                                     LZ77.MAXCODEWIDTH,
                                                     LZ77.NUMLENCODES)
        block_size = bs.read_bits(15)
        return (block_size, main_syms, main_widths, len_syms, len_widths)

    def _read_syms(self, bs):
        block_size, main_syms, main_widths, len_syms, len_widths = \
                self._read_tabs(bs)
        for i in range(block_size):
            symbol = main_syms[bs.peek_bits(LZ77.MAXCODEWIDTH)]
            bs.skip_bits(main_widths[symbol])

            if symbol > 255:
                arg2 = None
                if symbol == LZ77.TYPECODE:
                    typecode = bs.read_bits(8)
                    arg1 = typecode
                    if typecode == ACE.MODE_LZ77_DELTA:
                        arg2 = bs.read_bits(25)
                    elif typecode == ACE.MODE_LZ77_EXE:
                        arg2 = bs.read_bits(8)
                else:
                    if symbol > 259:
                        # most significant bit is always 1 and not encoded
                        bits = symbol - 260
                        if bits >= 2:
                            arg2 = bs.read_bits(bits - 1) + (1 << (bits - 1))
                        else:
                            arg2 = bits
                    arg1 = len_syms[bs.peek_bits(LZ77.MAXCODEWIDTH)]
                    bs.skip_bits(len_widths[arg1])
                self.__symbols.append(symbol, arg1, arg2)
            else:
                self.__symbols.append(symbol)

    def read(self, bs, want_size):
        """
        Read a block of LZ77 compressed data from BitStream *bs*.
        Reading will stop when *want_size* output bytes can be provided,
        or when a block ends, i.e. when a mode instruction is found.
        Returns a tuple of the output bytes and the mode instruction.
        """
        assert want_size > 0
        have_size = 0

        if len(self.__leftover) > 0:
            self.__dictionary.extend(self.__leftover)
            have_size += len(self.__leftover)
            self.__leftover = []

        next_mode = None
        while   have_size < want_size or \
                len(self.__symbols) == 0 or \
                self.__symbols.next_symbol == LZ77.TYPECODE:
            if len(self.__symbols) == 0:
                if have_size == want_size:
                    # don't read symbols when want_size is satisfied;
                    # this will mean that we don't read the type change if it
                    # directly follows the symbols
                    # to fix this, ensure caller handles zero length chunk
                    # by immediately switching modes in the DELTA reading loop
                    break
                self._read_syms(bs)
                continue

            sym = next(self.__symbols)

            if sym.symbol > 255:
                if sym.symbol == LZ77.TYPECODE:
                    typecode = sym.typecode
                    if typecode == ACE.MODE_LZ77_DELTA:
                        delta_dist = sym.typeargs >> 17
                        delta_len = sym.typeargs & 0x1FFFF
                        next_mode = (typecode, delta_dist, delta_len)
                    elif typecode == ACE.MODE_LZ77_EXE:
                        exe_mode = sym.typeargs
                        next_mode = (typecode, exe_mode)
                    else:
                        next_mode = (typecode,)
                    break

                copy_len = sym.len
                if sym.symbol > 259:
                    copy_dist = sym.dist
                    self.__disthist.append(copy_dist)
                    if copy_dist <= LZ77.MAXDISTATLEN2:
                        copy_len += 2
                    elif copy_dist <= LZ77.MAXDISTATLEN3:
                        copy_len += 3
                    else:
                        copy_len += 4
                else:
                    offset = sym.symbol & 0xFF
                    copy_dist = self.__disthist.retrieve(sym.symbol & 0xFF)
                    if offset > 1:
                        copy_len += 3
                    else:
                        copy_len += 2
                copy_dist += 1
                source_pos = len(self.__dictionary) - copy_dist
                zero_filled = 0
                if source_pos < 0:
                    for i in range(copy_dist - len(self.__dictionary)):
                        self.__dictionary.append(0)
                        have_size += 1
                        source_pos += 1
                        copy_len -= 1
                        zero_filled += 1
                for i in range(source_pos, source_pos + copy_len):
                    self.__dictionary.append(self.__dictionary[i])
                    have_size += 1
            else:
                self.__dictionary.append(sym.symbol)
                have_size += 1
        if have_size > want_size:
            diff = have_size - want_size
            self.__leftover = self.__dictionary[-diff:]
            self.__dictionary = self.__dictionary[:-diff]
            have_size -= diff
        if have_size > 0:
            assert have_size <= len(self.__dictionary)
            chunk = self.__dictionary[-have_size:]
        else:
            chunk = []
        self._dic_truncate()
        return (chunk, next_mode)



class Sound:
    """
    ACE 2.0 SOUND mode decompression engine.
    """

    class Channel:
        """
        Decompression parameters and methods for a single audio channel.
        """
        def __init__(self, sound, idx):
            self.__sound = sound
            self.__chanidx = idx
            self.reinit()

        def reinit(self):
            self.__pred_dif_cnt         = [0] * 2
            self.__last_pred_dif_cnt    = [0] * 2
            self.__rar_dif_cnt          = [0] * 4
            self.__rar_coeff            = [0] * 4
            self.__rar_dif              = [0] * 9
            self.__byte_count           = 0
            self.__last_byte            = 0
            self.__last_delta           = 0
            self.__adapt_model_cnt      = 0
            self.__adapt_model_use      = 0
            self.__get_state            = 0
            self.__get_code             = 0

        def model(self):
            model = self.__get_state << 1
            if model == 0:
                model += self.__adapt_model_use
            model += 3 * self.__chanidx
            return model

        def _get(self, bs):
            if self.__get_state != 2:
                self.__get_code = self.__sound._get_symbol(bs, self.model())
                if self.__get_code == Sound.TYPECODE:
                    next_type = bs.read_bits(8)
                    if next_type == ACE.MODE_LZ77_DELTA:
                        delta_dist = bs.read_bits(8)
                        delta_len = bs.read_bits(17)
                        next_mode = (next_type, delta_dist, delta_len)
                    elif next_type == ACE.MODE_LZ77_EXE:
                        exe_mode = bs.read_bits(8)
                        next_mode = (next_type, exe_mode)
                    else:
                        next_mode = (next_type,)
                    return next_mode

            if self.__get_state == 0:
                if self.__get_code >= Sound.RUNLENCODES:
                    value = self.__get_code - Sound.RUNLENCODES
                    self.__adapt_model_cnt = \
                        (self.__adapt_model_cnt * 7 >> 3) + value
                    if self.__adapt_model_cnt > 40:
                        self.__adapt_model_use = 1
                    else:
                        self.__adapt_model_use = 0
                else:
                    self.__get_state = 2
            elif self.__get_state == 1:
                value = self.__get_code
                self.__get_state = 0

            if self.__get_state == 2:
                if self.__get_code == 0:
                    self.__get_state = 1
                else:
                    self.__get_code -= 1
                value = 0

            if value & 1:
                return 255 - (value >> 1)
            else:
                return value >> 1

        def _rar_predict(self):
            if self.__pred_dif_cnt[0] > self.__pred_dif_cnt[1]:
                return self.__last_byte
            else:
                return self._get_predicted_char()

        def _rar_adjust(self, char):
            self.__byte_count += 1
            pred_char = self._get_predicted_char()
            pred_dif = (pred_char - char) << 3
            self.__rar_dif[0] += abs(pred_dif - self.__rar_dif_cnt[0])
            self.__rar_dif[1] += abs(pred_dif + self.__rar_dif_cnt[0])
            self.__rar_dif[2] += abs(pred_dif - self.__rar_dif_cnt[1])
            self.__rar_dif[3] += abs(pred_dif + self.__rar_dif_cnt[1])
            self.__rar_dif[4] += abs(pred_dif - self.__rar_dif_cnt[2])
            self.__rar_dif[5] += abs(pred_dif + self.__rar_dif_cnt[2])
            self.__rar_dif[6] += abs(pred_dif - self.__rar_dif_cnt[3])
            self.__rar_dif[7] += abs(pred_dif + self.__rar_dif_cnt[3])
            self.__rar_dif[8] += abs(pred_dif)

            self.__pred_dif_cnt[0] += \
                self.__sound.quantizer[c_uchar(pred_dif >> 3)]
            self.__pred_dif_cnt[1] += \
                self.__sound.quantizer[c_uchar(self.__last_byte - char)]
            self.__last_delta = (char - self.__last_byte)
            self.__last_byte = char

            if self.__byte_count & 0x1F == 0:
                min_dif = 0xFFFF
                for i in reversed(range(9)):
                    if self.__rar_dif[i] <= min_dif:
                        min_dif = self.__rar_dif[i]
                        min_dif_pos = i
                    self.__rar_dif[i] = 0
                if min_dif_pos != 8:
                    i = min_dif_pos >> 1
                    if min_dif_pos & 1 == 0:
                        if self.__rar_coeff[i] >= -16:
                            self.__rar_coeff[i] -= 1
                    else:
                        if self.__rar_coeff[i] <= 16:
                            self.__rar_coeff[i] += 1
                if self.__byte_count & 0xFF == 0:
                    for i in range(2):
                        self.__pred_dif_cnt[i] -= self.__last_pred_dif_cnt[i]
                        self.__last_pred_dif_cnt[i] = self.__pred_dif_cnt[i]

            self.__rar_dif_cnt[3] = self.__rar_dif_cnt[2]
            self.__rar_dif_cnt[2] = self.__rar_dif_cnt[1]
            self.__rar_dif_cnt[1] = self.__last_delta - self.__rar_dif_cnt[0]
            self.__rar_dif_cnt[0] = self.__last_delta

        def _get_predicted_char(self):
            return c_uchar((8 * self.__last_byte + \
                            self.__rar_coeff[0] * self.__rar_dif_cnt[0] + \
                            self.__rar_coeff[1] * self.__rar_dif_cnt[1] + \
                            self.__rar_coeff[2] * self.__rar_dif_cnt[2] + \
                            self.__rar_coeff[3] * self.__rar_dif_cnt[3]) >> 3)


    RUNLENCODES         = 32
    TYPECODE            = 256 + RUNLENCODES
    NUMCODES            = 256 + RUNLENCODES + 1
    MAXCODEWIDTH        = 10
    MAXCHANNELS         = 3
    NUMCHANNELS         = (1, 2, 3, 3)
    USECHANNELS         = ((0, 0, 0, 0),
                           (0, 1, 0, 1),
                           (0, 1, 0, 2),
                           (1, 0, 2, 0))

    def __init__(self):
        self.quantizer = [None] * 256
        self.quantizer[0] = 0
        for i in range(1, 129):
            self.quantizer[256 - i] = self.quantizer[i] = i.bit_length()
        self.__channels = [self.Channel(self, i) for i in range(Sound.MAXCHANNELS)]

    def reinit(self, mode):
        """
        Reinitialize the SOUND decompression engine.
        Reset all data dependent state to initial values.
        """
        for channel in self.__channels:
            channel.reinit()
        self.__mode           = mode - ACE.MODE_SOUND_8
        num_models            = Sound.NUMCHANNELS[self.__mode] * 3
        self.__huff_symbols   = [None] * num_models
        self.__huff_widths    = [None] * num_models
        self.__blocksize      = 0

    def _read_tabs(self, bs):
        for i in range(len(self.__huff_symbols)):
            self.__huff_symbols[i], self.__huff_widths[i] = \
                    Huffman.read_widths(bs, Sound.MAXCODEWIDTH, Sound.NUMCODES)
        self.__blocksize = bs.read_bits(15)

    def _get_symbol(self, bs, model):
        if self.__blocksize == 0:
            self._read_tabs(bs)

        symbol = self.__huff_symbols[model][bs.peek_bits(Sound.MAXCODEWIDTH)]
        bs.skip_bits(self.__huff_widths[model][symbol])
        self.__blocksize -= 1
        return symbol

    def read(self, bs, want_size):
        """
        Read a block of SOUND compressed data from BitStream *bs*.
        Reading will stop when *want_size* output bytes can be provided,
        or when a block ends, i.e. when a mode instruction is found.
        Returns a tuple of the output bytes and the mode instruction.
        """
        assert want_size > 0
        chunk = []
        for i in range(want_size & 0xFFFFFFFC):
            channel = Sound.USECHANNELS[self.__mode][i % 4]
            value = self.__channels[channel]._get(bs)
            if isinstance(value, tuple):
                return (chunk, value)
            sample = c_uchar(value + self.__channels[channel]._rar_predict())
            chunk.append(sample)
            self.__channels[channel]._rar_adjust(sample)
        return (chunk, None)



class Pic:
    """
    ACE 2.0 PIC mode decompression engine.
    """
    NUMCONTEXTS         = 365
    N0                  = 128
    S1                  = 3
    S2                  = 7
    S3                  = 21

    def __init__(self):
        self.__dif_bit_width = [0] * 256
        for i in range(0, 128):
            self.__dif_bit_width[i] = (2 * i).bit_length()
        for i in range(-128, 0):
            self.__dif_bit_width[i] = (- 2 * i - 1).bit_length()
        self.__quantizer   = [0] * 511
        self.__quantizer9  = [0] * 511
        self.__quantizer81 = [0] * 511
        for i in range(-255, 256):
            if   i <= -Pic.S3:
                self.__quantizer[255+i] = -4
            elif i <= -Pic.S2:
                self.__quantizer[255+i] = -3
            elif i <= -Pic.S1:
                self.__quantizer[255+i] = -2
            elif i <= -1:
                self.__quantizer[255+i] = -1
            elif i == 0:
                self.__quantizer[255+i] =  0
            elif i < Pic.S1:
                self.__quantizer[255+i] =  1
            elif i < Pic.S2:
                self.__quantizer[255+i] =  2
            elif i < Pic.S3:
                self.__quantizer[255+i] =  3
            else:
                self.__quantizer[255+i] =  4
        for i in range(-255, 256):
            self.__quantizer9 [255+i] = 9 * self.__quantizer [255+i]
        for i in range(-255, 256):
            self.__quantizer81[255+i] = 9 * self.__quantizer9[255+i]

    class Context:
        def __init__(self):
            self.used_counter = 0
            self.predictor_number = 0
            self.average_counter = 4
            self.error_counters = [0] * 4

    class Model:
        def __init__(self):
            self.contexts = [Pic.Context() for i in range(Pic.NUMCONTEXTS)]


    def reinit(self, bs):
        """
        Reinitialize the PIC decompression engine.
        Read width and planes from BitStream *bs* and reset all data dependent
        state to initial values.
        """
        self.__width = bs.golomb_rice(12)
        self.__planes = bs.golomb_rice(2)
        self.__lastdata = [0] * (self.__width + self.__planes)
        self.__leftover = []
        self.__models = [self.Model(), self.Model()]
        self.__pixel_a = 0
        self.__pixel_b = 0
        self.__pixel_c = 0
        self.__pixel_d = 0
        self.__pixel_x = 0

    def _set_pixels(self, use_predictor, val, prev_val):
        self.__pixel_d = val
        if use_predictor == 1:
            self.__pixel_a = 128
            self.__pixel_b = 128
            self.__pixel_c = 128
            self.__pixel_x = 128
            self.__pixel_d -= prev_val - 128
            self.__pixel_d &= 0xFF
        elif use_predictor == 2:
            self.__pixel_a = 128
            self.__pixel_b = 128
            self.__pixel_c = 128
            self.__pixel_x = 128
            self.__pixel_d -= (prev_val * 11 >> 4) - 128
            self.__pixel_d &= 0xFF
        else:
            self.__pixel_a = 0
            self.__pixel_b = 0
            self.__pixel_c = 0
            self.__pixel_x = 0

    def _rotate_pixels(self):
        self.__pixel_c = self.__pixel_a
        self.__pixel_a = self.__pixel_d
        self.__pixel_b = self.__pixel_x

    def _predict(self, use_predictor):
        if use_predictor == 0:
            return self.__pixel_a
        elif use_predictor == 1:
            return self.__pixel_b
        elif use_predictor == 2:
            return (self.__pixel_a + self.__pixel_b) >> 1
        elif use_predictor == 3:
            return c_uchar(self.__pixel_a + self.__pixel_b - self.__pixel_c)

    def _produce(self, use_predictor, prev_val):
        if use_predictor == 0:
            return self.__pixel_x
        elif use_predictor == 1:
            return c_uchar(self.__pixel_x + prev_val - 128)
        elif use_predictor == 2:
            return c_uchar(self.__pixel_x + (prev_val * 11 >> 4) - 128)

    def _get_pixel_context(self, use_predictor, val, prev_val):
        self.__pixel_d = val
        if use_predictor == 1:
            self.__pixel_d -= prev_val - 128
        elif use_predictor == 2:
            self.__pixel_d -= (prev_val * 11 >> 4) - 128
        self.__pixel_d &= 0xFF

        ctx = self.__quantizer81[255 + self.__pixel_d - self.__pixel_a] + \
              self.__quantizer9 [255 + self.__pixel_a - self.__pixel_c] + \
              self.__quantizer  [255 + self.__pixel_c - self.__pixel_b]
        return abs(ctx)

    def _get_pixel_x(self, bs, context):
        context.used_counter += 1

        r = c_div(context.average_counter, context.used_counter)
        epsilon = bs.golomb_rice(r.bit_length(), signed=True)
        predicted = self._predict(context.predictor_number)
        pixel_x = c_uchar(predicted + epsilon)

        for i in range(len(context.error_counters)):
            context.error_counters[i] += \
                    self.__dif_bit_width[c_uchar(pixel_x - self._predict(i))]
            if i == 0 or context.error_counters[i] < \
                         context.error_counters[best_predictor]:
                best_predictor = i

        if any([ec & 0x80 for ec in context.error_counters]):
            for i in range(len(context.error_counters)):
                context.error_counters[i] >>= 1

        context.predictor_number = best_predictor
        context.average_counter += abs(epsilon)

        if context.used_counter == Pic.N0:
            context.used_counter >>= 1
            context.average_counter >>= 1

        return pixel_x

    def _line(self, bs):
        data = [0] * (self.__width + self.__planes)
        for plane in range(self.__planes):
            if plane == 0:
                use_model = 0
                use_predictor = 0
            else:
                use_model = 1
                use_predictor = bs.read_bits(2)

            self._set_pixels(use_predictor,
                             self.__lastdata[plane],
                             self.__lastdata[plane - 1])

            for col in range(plane, self.__width, self.__planes):
                self._rotate_pixels()
                use_context = self._get_pixel_context(use_predictor,
                        self.__lastdata[self.__planes + col],
                        self.__lastdata[self.__planes + col - 1])
                context = self.__models[use_model].contexts[use_context]
                self.__pixel_x = self._get_pixel_x(bs, context)

                data[col] = self._produce(use_predictor, data[col - 1])

        self.__lastdata = data
        return data[:self.__width]

    def read(self, bs, want_size):
        """
        Read a block of PIC compressed data from BitStream *bs*.
        Reading will stop when *want_size* output bytes can be provided,
        or when a block ends, i.e. when a mode instruction is found.
        Returns a tuple of the output bytes and the mode instruction.
        """
        assert want_size > 0
        next_mode = None
        chunk = []
        if len(self.__leftover) > 0:
            chunk.extend(self.__leftover)
            self.__leftover = []
        while len(chunk) < want_size:
            if bs.read_bits(1) == 0:
                next_type = bs.read_bits(8)
                if next_type == ACE.MODE_LZ77_DELTA:
                    delta_dist = bs.read_bits(8)
                    delta_len = bs.read_bits(17)
                    next_mode = (next_type, delta_dist, delta_len)
                elif next_type == ACE.MODE_LZ77_EXE:
                    exe_mode = bs.read_bits(8)
                    next_mode = (next_type, exe_mode)
                else:
                    next_mode = (next_type,)
                break
            data = self._line(bs)
            n = min(want_size - len(chunk), len(data))
            if n == len(data):
                chunk.extend(data)
            else:
                chunk.extend(data[0:n])
                self.__leftover = data[n:]
        return (chunk, next_mode)



class ACE:
    """
    Core decompression engine for ACE compression up to version 2.0.
    """
    MODE_LZ77_NORM          = 0     # LZ77
    MODE_LZ77_DELTA         = 1     # LZ77 after byte reordering
    MODE_LZ77_EXE           = 2     # LZ77 after patching JMP/CALL targets
    MODE_SOUND_8            = 3     # 8 bit sound compression
    MODE_SOUND_16           = 4     # 16 bit sound compression
    MODE_SOUND_32A          = 5     # 32 bit sound compression, variant 1
    MODE_SOUND_32B          = 6     # 32 bit sound compression, variant 2
    MODE_PIC                = 7     # picture compression
    MODE_STRINGS            = ('LZ77_NORMAL', 'LZ77_DELTA', 'LZ77_EXE',
                               'SOUND_8', 'SOUND_16', 'SOUND_32A', 'SOUND_32B',
                               'PIC')

    @staticmethod
    def mode_str(mode):
        try:
            return ACE.MODE_STRINGS[mode]
        except IndexError:
            return '?'

    def __init__(self):
        self.__lz77 = LZ77()
        self.__sound = Sound()
        self.__pic = Pic()

    def decompress_stored(self, f, packsize, filesize, params):
        """
        Decompress data compressed using the store method from file-like-object
        *f* containing *packsize* compressed bytes that will be decompressed to
        *filesize* bytes.  Decompressed data will be yielded in blocks of
        undefined size upon availability.
        """
        self.__lz77.set_dicbits((params & 15) + 10)
        producedsize = 0
        while producedsize < filesize:
            wantsize = min(filesize - producedsize, FILE_BLOCKSIZE)
            outchunk = f.read(wantsize)
            if len(outchunk) == 0:
                raise TruncatedArchiveError()
            self.__lz77.dic_copy(outchunk)
            yield outchunk
            producedsize += len(outchunk)

    def decompress_lz77(self, f, packsize, filesize, params):
        """
        Decompress data compressed using the ACE 1.0 legacy LZ77 method from
        file-like-object *f* containing *packsize* compressed bytes that will
        be decompressed to *filesize* bytes.  Decompressed data will be yielded
        in blocks of undefined size upon availability.
        """
        self.__lz77.set_dicbits((params & 15) + 10)
        self.__lz77.reinit()
        bs = BitStream(f, packsize)
        producedsize = 0
        while producedsize < filesize:
            outchunk, next_mode = self.__lz77.read(bs, filesize)
            if next_mode:
                raise CorruptArchiveError()
            yield outchunk
            producedsize += len(outchunk)

    def decompress_blocked(self, f, packsize, filesize, params):
        """
        Decompress data compressed using the ACE 2.0 blocked method from
        file-like-object *f* containing *packsize* compressed bytes that will
        be decompressed to *filesize* bytes.  Decompressed data will be yielded
        in blocks of undefined size upon availability.
        """
        bs = BitStream(f, packsize)
        self.__lz77.set_dicbits((params & 15) + 10)
        self.__lz77.reinit()

        # LZ77_EXE
        exe_leftover = []

        # LZ77_DELTA
        last_delta = 0

        next_mode = None
        mode_type = 0
        mode_args = ()

        producedsize = 0
        while producedsize < filesize:
            if next_mode != None:
                if mode_type != next_mode[0]:
                    if next_mode[0] in [ACE.MODE_SOUND_8,
                                        ACE.MODE_SOUND_16,
                                        ACE.MODE_SOUND_32A,
                                        ACE.MODE_SOUND_32B]:
                        self.__sound.reinit(next_mode[0])
                    elif next_mode[0] == ACE.MODE_PIC:
                        self.__pic.reinit(bs)

                mode_type = next_mode[0]
                mode_args = next_mode[1:]
                next_mode = None

            outchunk = []
            if mode_type == ACE.MODE_LZ77_DELTA:
                delta_dist, delta_len = mode_args
                delta = []
                while len(delta) < delta_len:
                    chunk, nm = self.__lz77.read(bs, delta_len - len(delta))
                    delta.extend(chunk)
                    if nm != None:
                        assert next_mode == None
                        next_mode = nm
                assert len(delta) == delta_len

                for i in range(len(delta)):
                    delta[i] = c_uchar(delta[i] + last_delta)
                    last_delta = delta[i]

                delta_plane = 0
                delta_plane_pos = 0
                delta_plane_size = delta_len // delta_dist
                while delta_plane_pos < delta_plane_size:
                    while delta_plane < delta_len:
                        outchunk.append(delta[delta_plane + delta_plane_pos])
                        delta_plane += delta_plane_size
                    delta_plane = 0
                    delta_plane_pos += 1
                # end of ACE.MODE_LZ77_DELTA

            elif mode_type in [ACE.MODE_LZ77_NORM, ACE.MODE_LZ77_EXE]:
                if len(exe_leftover) > 0:
                    outchunk.extend(exe_leftover)
                    exe_leftover = []
                chunk, next_mode = self.__lz77.read(bs,
                        filesize - producedsize - len(outchunk))
                outchunk.extend(chunk)

                if mode_type == ACE.MODE_LZ77_EXE:
                    exe_mode = mode_args[0]
                    it = iter(range(len(outchunk)))
                    for i in it:
                        if i + 4 >= len(outchunk):
                            break
                        if outchunk[i] == 0xE8:   # CALL rel16/rel32
                            pos = producedsize + i
                            if exe_mode == 0:
                                # rel16
                                assert i + 2 < len(outchunk)
                                rel16 = outchunk[i+1] + (outchunk[i+2] << 8)
                                rel16 = (rel16 - pos) & 0xFFFF
                                outchunk[i+1] =  rel16       & 0xFF
                                outchunk[i+2] = (rel16 >> 8) & 0xFF
                                next(it); next(it)
                            else:
                                # rel32
                                assert i + 4 < len(outchunk)
                                rel32 =  outchunk[i+1]        + \
                                        (outchunk[i+2] <<  8) + \
                                        (outchunk[i+3] << 16) + \
                                        (outchunk[i+4] << 24)
                                rel32 = (rel32 - pos) & 0xFFFFFFFF
                                outchunk[i+1] =  rel32        & 0xFF
                                outchunk[i+2] = (rel32 >>  8) & 0xFF
                                outchunk[i+3] = (rel32 >> 16) & 0xFF
                                outchunk[i+4] = (rel32 >> 24) & 0xFF
                                next(it); next(it); next(it); next(it)
                        elif outchunk[i] == 0xE9: # JMP  rel16/rel32
                            pos = producedsize + i
                            # rel16
                            assert i + 2 < len(outchunk)
                            rel16 = outchunk[i+1] + (outchunk[i+2] << 8)
                            rel16 = (rel16 - pos) & 0xFFFF
                            outchunk[i+1] =  rel16       & 0xFF
                            outchunk[i+2] = (rel16 >> 8) & 0xFF
                            next(it); next(it)
                    # store max 4 bytes for next loop; this can happen when
                    # changing between different exe modes after the opcode
                    # but before completing the machine instruction
                    for i in it:
                        assert i + 4 >= len(outchunk)
                        if outchunk[i] == 0xE8 or outchunk[i] == 0xE9:
                            exe_leftover = outchunk[i:]
                            outchunk = outchunk[:i]
                    # end of ACE.MODE_LZ77_EXE
                # end of ACE.MODE_LZ77_NORM or ACE.MODE_LZ77_EXE

            elif mode_type in [ACE.MODE_SOUND_8,   ACE.MODE_SOUND_16,
                               ACE.MODE_SOUND_32A, ACE.MODE_SOUND_32B]:
                outchunk, next_mode = self.__sound.read(bs,
                                                        filesize - producedsize)
                self.__lz77.dic_copy(outchunk)
                # end of ACE.MODE_SOUND_*

            elif mode_type == ACE.MODE_PIC:
                outchunk, next_mode = self.__pic.read(bs,
                                                      filesize - producedsize)
                self.__lz77.dic_copy(outchunk)
                # end of ACE.MODE_PIC

            else:
                raise CorruptedArchiveError("unknown mode type: %i" % mode_type)

            yield bytes(outchunk)
            producedsize += len(outchunk)
            # end of block loop
        return producedsize



class Header:
    """
    Base class for all ACE file format headers.
    """
    MAGIC               = b'**ACE**'

    TYPE_MAIN           = 0
    TYPE_FILE32         = 1
    TYPE_RECOVERY32     = 2
    TYPE_FILE64         = 3
    TYPE_RECOVERY64A    = 4
    TYPE_RECOVERY64B    = 5
    TYPE_STRINGS        = ('MAIN', 'FILE32', 'RECOVERY32',
                           'FILE64', 'RECOVERY64A', 'RECOVERY64B')

    FLAG_ADDSIZE        = 1 <<  0   # 1 iff addsize field present           MFR
    FLAG_COMMENT        = 1 <<  1   # 1 iff comment present                 MF-
    FLAG_64BIT          = 1 <<  2   # 1 iff 64bit addsize field             -FR
    FLAG_V20FORMAT      = 1 <<  8   # 1 iff ACE 2.0 format                  M--
    FLAG_SFX            = 1 <<  9   # 1 iff self extracting archive         M--
    FLAG_LIMITSFXJR     = 1 << 10   # 1 iff dict size limited to 256K       M--
    FLAG_NTSECURITY     = 1 << 10   # 1 iff NTFS security data present      -F-
    FLAG_MULTIVOLUME    = 1 << 11   # 1 iff archive has multiple volumes    M--
    FLAG_ADVERT         = 1 << 12   # 1 iff advert string present           M--
    FLAG_CONTPREV       = 1 << 12   # 1 iff continued from previous volume  -F-
    FLAG_RECOVERY       = 1 << 13   # 1 iff recovery record present         M--
    FLAG_CONTNEXT       = 1 << 13   # 1 iff continued in next volume        -F-
    FLAG_LOCKED         = 1 << 14   # 1 iff archive is locked               M--
    FLAG_PASSWORD       = 1 << 14   # 1 iff password encrypted              -F-
    FLAG_SOLID          = 1 << 15   # 1 iff archive is solid                MF-
    FLAG_STRINGS_M      = ('ADDSIZE',   'COMMENT',  '4',          '8',
                           '16',        '32',       '64',         '128',
                           'V20FORMAT', 'SFX',      'LIMITSFXJR', 'MULTIVOLUME',
                           'ADVERT',    'RECOVERY', 'LOCKED',     'SOLID')
    FLAG_STRINGS_F      = ('ADDSIZE',   'COMMENT',  '64BIT',      '8',
                           '16',        '32',       '64',         '128',
                           '256',       '512',      'NTSECURITY', '2048',
                           'CONTPREV',  'CONTNEXT', 'PASSWORD',   'SOLID')
    FLAG_STRINGS_R      = ('ADDSIZE',   '2',        '64BIT',      '8',
                           '16',        '32',       '64',         '128',
                           '256',       '512',      '1024',       '2048',
                           '4096',      '8192',     '16384',      '32768')
    FLAG_STRINGS_BYTYPE = (FLAG_STRINGS_M, FLAG_STRINGS_F, FLAG_STRINGS_R,
                           FLAG_STRINGS_F, FLAG_STRINGS_R, FLAG_STRINGS_R)

    HOST_MSDOS          =  0
    HOST_OS2            =  1
    HOST_WIN32          =  2
    HOST_UNIX           =  3
    HOST_MAC_OS         =  4
    HOST_WIN_NT         =  5
    HOST_PRIMOS         =  6
    HOST_APPLE_GS       =  7
    HOST_ATARI          =  8
    HOST_VAX_VMS        =  9
    HOST_AMIGA          = 10
    HOST_NEXT           = 11
    HOST_LINUX          = 12
    HOST_STRINGS        = ('MS-DOS', 'OS/2', 'Win32', 'Unix', 'Mac OS',
                           'Win NT', 'Primos', 'Apple GS', 'ATARI', 'VAX VMS',
                           'AMIGA', 'NeXT', 'Linux')

    COMP_STORE          = 0
    COMP_LZ77           = 1
    COMP_BLOCKED        = 2
    COMP_STRINGS        = ('store', 'lz77', 'blocked')

    QUAL_STORE          = 0
    QUAL_FASTEST        = 1
    QUAL_FAST           = 2
    QUAL_NORMAL         = 3
    QUAL_GOOD           = 4
    QUAL_BEST           = 5
    QUAL_STRINGS        = ('store', 'fastest', 'fast', 'normal', 'good', 'best')

    # winnt.h
    ATTR_READONLY               = 0x00000001
    ATTR_HIDDEN                 = 0x00000002
    ATTR_SYSTEM                 = 0x00000004
    ATTR_VOLUME_ID              = 0x00000008
    ATTR_DIRECTORY              = 0x00000010
    ATTR_ARCHIVE                = 0x00000020
    ATTR_DEVICE                 = 0x00000040
    ATTR_NORMAL                 = 0x00000080
    ATTR_TEMPORARY              = 0x00000100
    ATTR_SPARSE_FILE            = 0x00000200
    ATTR_REPARSE_POINT          = 0x00000400
    ATTR_COMPRESSED             = 0x00000800
    ATTR_OFFLINE                = 0x00001000
    ATTR_NOT_CONTENT_INDEXED    = 0x00002000
    ATTR_ENCRYPTED              = 0x00004000
    ATTR_INTEGRITY_STREAM       = 0x00008000
    ATTR_VIRTUAL                = 0x00010000
    ATTR_NO_SCRUB_DATA          = 0x00020000
    ATTR_EA                     = 0x00040000
    ATTR_STRINGS                = ('READONLY', 'HIDDEN', 'SYSTEM', 'VOLUME_ID',
                                   'DIRECTORY', 'ARCHIVE', 'DEVICE', 'NORMAL',
                                   'TEMPORARY', 'SPARSE_FILE',
                                   'REPARSE_POINT', 'COMPRESSED',
                                   'OFFLINE', 'NOT_CONTENT_INDEXED',
                                   'ENCRYPTED', 'INTEGRITY_STREAM',
                                   'VIRTUAL', 'NO_SCRUB_DATA', 'EA')

    @staticmethod
    def _format_bitfield(strings, field):
        labels = []
        for i in range(field.bit_length()):
            bit = 1 << i
            if field & bit == bit:
                try:
                    labels.append(strings[i])
                except IndexError:
                    labels.append(str(bit))
        return '|'.join(labels)

    def __init__(self, crc, size, type, flags):
        self.hdr_crc    = crc       # uint16    header crc without crc,sz
        self.hdr_size   = size      # uint16    header size without crc,sz
        self.hdr_type   = type      # uint8
        self.hdr_flags  = flags     # uint16

    def __str__(self):
        return """header
    hdr_crc     0x%04x
    hdr_size    %i
    hdr_type    0x%02x        %s
    hdr_flags   0x%04x      %s""" % (
                self.hdr_crc,
                self.hdr_size,
                self.hdr_type, self.hdr_type_str,
                self.hdr_flags, self.hdr_flags_str)

    def flag(self, flag):
        return self.hdr_flags & flag == flag

    @property
    def hdr_type_str(self):
        try:
            return Header.TYPE_STRINGS[self.hdr_type]
        except IndexError:
            return '?'

    @property
    def hdr_flags_str(self):
        try:
            strings = self.FLAG_STRINGS_BYTYPE[self.hdr_type]
            return self._format_bitfield(strings, self.hdr_flags)
        except IndexError:
            return '?'



class UnknownHeader(Header):
    pass



class MainHeader(Header):
    def __init__(self, *args):
        super().__init__(*args)
        self.magic      = None      # uint8[7]  **ACE**
        self.eversion   = None      # uint8     extract version
        self.cversion   = None      # uint8     creator version
        self.host       = None      # uint8     platform
        self.volume     = None      # uint8     volume number
        self.datetime   = None      # uint32    date/time in MS-DOS format
        self.reserved1  = None      # uint8[8]
        self.advert     = ''        # [uint8]   optional
        self.comment    = ''        # [uint16]  optional, compressed
        self.reserved2  = None      # [?]       optional

    def __str__(self):
        return super().__str__() + """
    magic       %s
    eversion    %i
    cversion    %i
    host        0x%02x        %s
    volume      %i
    date        0x%08x
    reserved1   %02x %02x %02x %02x %02x %02x %02x %02x
    advert      %s
    comment     %r
    reserved2   %r""" % (
                self.magic,
                self.eversion,
                self.cversion,
                self.host, self.host_str,
                self.volume,
                self.datetime,
                self.reserved1[0], self.reserved1[1],
                self.reserved1[2], self.reserved1[3],
                self.reserved1[4], self.reserved1[5],
                self.reserved1[6], self.reserved1[7],
                self.advert,
                self.comment,
                self.reserved2)

    @property
    def host_str(self):
        try:
            return Header.HOST_STRINGS[self.host]
        except IndexError:
            return '?'



class FileHeader(Header):
    def __init__(self, *args):
        super().__init__(*args)
        self.packsize   = None      # uint32|64 packed size
        self.origsize   = None      # uint32|64 original size
        self.datetime   = None      # uint32    ctime
        self.attribs    = None      # uint32    file attributes
        self.crc32      = None      # uint32    checksum over compressed file
        self.comptype   = None      # uint8     compression type
        self.compqual   = None      # uint8     compression quality
        self.params     = None      # uint16    decompression parameters
        self.reserved1  = None      # uint16
        self.filename   = None      # [uint16]
        self.comment    = ''        # [uint16]  optional, compressed
        self.reserved2  = None      # ?
        self.dataoffset = None      #           position of data after hdr

    def __str__(self):
        return super().__str__() + """
    packsize    %i
    origsize    %i
    datetime    0x%08x
    attribs     0x%08x  %s
    crc32       0x%08x
    comptype    0x%02x        %s
    compqual    0x%02x        %s
    params      0x%04x
    reserved1   0x%04x
    filename    %s
    comment     %r
    reserved2   %r""" % (
                self.packsize,
                self.origsize,
                self.datetime,
                self.attribs, self.attribs_str,
                self.crc32,
                self.comptype, self.comptype_str,
                self.compqual, self.compqual_str,
                self.params,
                self.reserved1,
                self.filename,
                self.comment,
                self.reserved2)

    def attrib(self, attrib):
        return self.attribs & attrib == attrib

    @property
    def attribs_str(self):
        return self._format_bitfield(Header.ATTR_STRINGS, self.attribs)

    @property
    def comptype_str(self):
        try:
            return Header.COMP_STRINGS[self.comptype]
        except IndexError:
            return '?'

    @property
    def compqual_str(self):
        try:
            return Header.QUAL_STRINGS[self.compqual]
        except IndexError:
            return '?'



class AceError(Exception):
    """
    Base class for all acefile errors.
    """
    pass

class MainHeaderNotFoundError(AceError):
    """
    The main ACE header marked by the magic bytes **ACE** could not be found.
    Either the *search* argument was to small or the archive is not an ACE
    format archive.
    """
    pass

class TruncatedArchiveError(AceError):
    """
    Archive is truncated.
    """
    pass

class CorruptedArchiveError(AceError):
    """
    Archive is corrupted.  Either a CRC check failed or an invalid value was
    read from the archive.
    """
    pass

class EncryptedArchiveError(AceError):
    """
    Archive member is encrypted but either no password was provided, or
    decompression failed with the given password.
    Also raised when processing an encrypted solid archive member out of order,
    when any previous archive member uses a different password than the archive
    member currently being accessed.
    """
    pass

class UnknownMethodError(AceError):
    """
    Data was compressed using an unknown compression method and therefore
    cannot be decompressed.
    """
    pass



class AceInfo:
    """
    Handle class which holds information on an archive member.
    """

    @staticmethod
    def _sanitize_filename(filename):
        """
        Sanitize filename for security and platform independence.
        """
        # treat null byte as filename terminator
        nullbyte = filename.find(chr(0))
        if nullbyte >= 0:
            filename = filename[0:nullbyte]
        # eliminate characters illegal on some platforms
        filename = filename.replace(':', '_')
        filename = filename.replace('<', '_')
        filename = filename.replace('>', '_')
        filename = filename.replace('"', '_')
        filename = filename.replace('?', '_')
        filename = filename.replace('*', '_')
        # ensure path separators are consistent with current platform
        if os.sep != '/':
            filename = filename.replace('/', os.sep)
        elif os.sep != '\\':
            filename = filename.replace('\\', os.sep)
        # eliminate ../ sequences to avoid path traversal attacks
        filename = filename.replace('..' + os.sep, '')
        return filename

    def __init__(self, idx, filehdr):
        self._idx           = idx
        self.orig_filename  = filehdr.filename
        self.filename       = self._sanitize_filename(filehdr.filename)
        self.size           = filehdr.origsize
        self.packsize       = filehdr.packsize
        self.mtime          = _dt_fromdos(filehdr.datetime)
        self.attribs        = filehdr.attribs
        self.comment        = filehdr.comment
        self.crc32          = filehdr.crc32
        self.comptype       = filehdr.comptype
        self.compqual       = filehdr.compqual
        self.params         = filehdr.params
        self.header         = filehdr

    def is_dir(self):
        """
        True iff AceInfo object refers to a directory.
        """
        return self.attribs & Header.ATTR_DIRECTORY != 0

    def is_reg(self):
        """
        True iff AceInfo object refers to a regular file.
        """
        return not self.is_dir()

    def is_enc(self):
        """
        True iff AceInfo object refers to an encrypted archive member.
        """
        return self.header.flag(Header.FLAG_PASSWORD)



class AceFile:
    """
    Open an ACE file and interact with its members in ways mostly compatible
    with both the tarfile and zipfile APIs.
    """

    @classmethod
    def open(cls, *args, **kvargs):
        """
        Alternative constructor for AceFile, aliased to acefile.open().
        """
        return cls(*args, **kvargs)

    def __init__(self, file, mode='r', search=524288):
        """
        Open archive from *file*, which is either a filename or seekable
        file-like object.  Only *mode* 'r' is implemented.
        If *search* is 0, the archive must start at position 0 in *file*,
        otherwise the first *search* bytes are searched for the magic bytes
        **ACE** that mark the ACE main header.  For compatibility with the
        official unace, 1024 sectors are searched by default.
        """
        if mode != 'r':
            raise NotImplementedError()
        if isinstance(file, str):
            self.__file = builtin_open(file, 'rb')
            self.__filename = file
        else:
            if not file.seekable():
                raise TypeError(
                        "file must be filename or seekable file-like object")
            self.__file = file
            self.__filename = '-'
        self.__file.seek(0, 2)
        self.__filesize = self.__file.tell()
        self.__main_header = None
        self.__file_headers = []
        self.__all_headers = []
        self._parse_headers(search)
        if self.__main_header == None:
            raise CorruptArchiveError()
        if self.__main_header.flag(Header.FLAG_MULTIVOLUME):
            raise NotImplementedError()
        self.__file_aceinfos = []
        for i in range(len(self.__file_headers)):
            self.__file_aceinfos.append(AceInfo(i, self.__file_headers[i]))
        self.__next_iter_idx = 0
        self.__next_read_idx = 0
        self.__ace = ACE()

    def __enter__(self):
        """
        Using AceFile as a context manager ensures that close() is called after
        leaving the block.
        """
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __iter__(self):
        """
        Using AceFile as an iterater will iterate over AceInfo objects for all
        archive members.
        """
        self.__next_iter_idx = 0
        return self

    def __next__(self):
        """
        Iterate to the next archive member's AceInfo object.
        """
        if self.__next_iter_idx >= len(self.__file_aceinfos):
            raise StopIteration()
        ai = self.__file_aceinfos[self.__next_iter_idx]
        self.__next_iter_idx += 1
        return ai

    def __repr__(self):
        return "<%s %r at %#x>" % (self.__class__.__name__,self.name,id(self))

    def close(self):
        """
        Close the archive and free all resources.
        """
        if self.__file != None:
            self.__file.close()
            self.__file = None

    def _get_file_idx(self, member):
        """
        Return index into self.__file_headers and self.__file_aceinfos
        corresponding to *member*, which can be an AceInfo object, a name
        or an index into the archive member list.
        """
        if isinstance(member, int):
            return member
        elif isinstance(member, AceInfo):
            return member._idx
        elif isinstance(member, str):
            return self._getmember_byname(member)._idx
        else:
            raise TypeError()

    def _getmember_byname(self, name):
        """
        Return an AceInfo object corresponding to archive member name *name*.
        Raise KeyError if *name* is not present in the archive.
        If *name* occurs multiple times in the archive, then the last occurence
        is returned.
        """
        match = None
        for ai in self.__file_aceinfos:
            if ai.filename == name:
                match = ai
        if match == None:
            raise KeyError()
        return match

    def getmember(self, member):
        """
        Return an AceInfo object corresponding to archive member *member*.
        Raise KeyError or IndexError if *member* is not found in archive.
        *Member* can refer to an AceInfo object, a member name or an index
        into the archive member list.
        If *member* is a name and it occurs multiple times in the archive,
        then the last member with matching filename is returned.
        """
        if isinstance(member, int):
            return self.__file_aceinfos[member]
        elif isinstance(member, AceInfo):
            return self.__file_aceinfos[member._idx]
        elif isinstance(member, str):
            return self._getmember_byname(member)
        else:
            raise TypeError()

    def getmembers(self):
        """
        Return a list of AceInfo objects for each member of the archive.
        The objects are in the same order as they are in the archive.
        """
        return self.__file_aceinfos

    def getnames(self):
        """
        Return a list of the names of all the members in the archive.
        """
        return [ai.filename for ai in self.__file_aceinfos]

    def extract(self, member, path=None, pwd=None):
        """
        Extract an archive member to *path* or the current working directory.
        *Member* can refer to an AceInfo object, a member name or an index
        into the archive member list.
        Returns the normalized path created (a directory or new file).
        Extracting members in a different order than they appear in a solid
        archive works but is very slow, because the decompressor needs to
        restart at the beginning of the solid archive to restore internal
        decompressor state.
        """
        idx = self._get_file_idx(member)
        ai = self.__file_aceinfos[idx]
        hdr = self.__file_headers[idx]

        if path != None:
            fn = os.path.join(path, ai.filename)
        else:
            fn = ai.filename
        if hdr.attrib(Header.ATTR_DIRECTORY):
            try:
                os.mkdir(fn)
            except FileExistsError:
                pass
        else:
            basedir = os.path.dirname(fn)
            if basedir != '':
                os.makedirs(basedir, exist_ok=True)
            with builtin_open(fn, 'wb') as f:
                for buf in self.readblocks(ai, pwd=pwd):
                    f.write(buf)

    def extractall(self, path=None, members=None, pwd=None):
        """
        Extract *members* or all members from archive to *path* or the current
        working directory.  Members can contain AceInfo objects, member names
        or indexes into the archive member list.
        """
        if members == None or members == []:
            members = self.__file_aceinfos
        else:
            if self.is_solid():
                # ensure members subset is in order of appearance
                sorted_members = []
                for member in self.__file_aceinfos:
                    if member in members or member.filename in members:
                        sorted_members.append(member)
                members = sorted_members
        for ai in members:
            self.extract(ai, path=path, pwd=pwd)

    def read(self, member, pwd=None):
        """
        Read the bytes of a member from the archive.
        *Member* can refer to an AceInfo object, a member name or an index
        into the archive member list.
        Using read() for large files is inefficient and may fail for very
        large files.  Using readblocks() to write the data to disk in blocks
        ensures that large files can be handled efficiently.
        Reading members in a different order than they appear in a solid
        archive works but is very slow, because the decompressor needs to
        restart at the beginning of the solid archive to restore internal
        decompressor state.
        """
        return b''.join(self.readblocks(member, pwd))

    def readblocks(self, member, pwd=None):
        """
        Read the archive by yielding blocks of bytes.
        *Member* can refer to an AceInfo object, a member name or an index
        into the archive member list.
        Reading members in a different order than they appear in a solid
        archive works but is very slow, because the decompressor needs to
        restart at the beginning of the solid archive to restore internal
        decompressor state.
        """
        idx = self._get_file_idx(member)
        ai = self.__file_aceinfos[idx]
        hdr = self.__file_headers[idx]

        # For solid archives, ensure the LZ77 state corresponds to the state
        # after extracting the previous file by re-starting extraction from
        # the beginning or the last extracted file.
        if self.is_solid() and self.__next_read_idx != idx:
            if self.__next_read_idx < idx:
                restart_idx = self.__next_read_idx
            else:
                restart_idx = self.__next_read_idx = 0
            for i in range(restart_idx, idx):
                if not self.test(self.__file_aceinfos[i]):
                    raise CorruptedArchiveError()

        if (not hdr.attrib(Header.ATTR_DIRECTORY)) and hdr.origsize > 0:
            if hdr.comptype == Header.COMP_STORE:
                decompressor = self.__ace.decompress_stored
            elif hdr.comptype == Header.COMP_LZ77:
                decompressor = self.__ace.decompress_lz77
            elif hdr.comptype == Header.COMP_BLOCKED:
                decompressor = self.__ace.decompress_blocked
            else:
                raise UnknownMethodError()

            self.__file.seek(hdr.dataoffset, 0)
            if hdr.flag(Header.FLAG_PASSWORD):
                if not pwd:
                    raise EncryptedArchiveError()
                f = EncryptedFileIO(self.__file, pwd)
            else:
                f = self.__file

            crc = AceCRC32()
            try:
                for block in decompressor(f, hdr.packsize, hdr.origsize,
                                          hdr.params):
                    crc += block
                    yield block
            except CorruptedArchiveError:
                if hdr.flag(Header.FLAG_PASSWORD):
                    raise EncryptedArchiveError()
                raise
            if crc != hdr.crc32:
                if hdr.flag(Header.FLAG_PASSWORD):
                    raise EncryptedArchiveError()
                raise CorruptedArchiveError()

        self.__next_read_idx += 1

    def test(self, member, pwd=None):
        """
        Read a file from the archive.  Returns False if any corruption was
        found, True if the header and decompression was okay.
        Raises EncryptedArchiveError if the archive member is encrypted but
        no password was provided.
        *Member* can refer to an AceInfo object, a member name or an index
        into the archive member list.
        Testing members in a different order than they appear in a solid
        archive works but is very slow, because the decompressor needs to
        restart at the beginning of the solid archive to restore internal
        decompressor state.
        """
        idx = self._get_file_idx(member)
        ai = self.__file_aceinfos[idx]
        try:
            for buf in self.readblocks(ai, pwd=pwd):
                pass
            return True
        except EncryptedArchiveError:
            raise
        except AceError:
            return False

    def testall(self, pwd=None):
        """
        Read all the files in the archive.  Returns the name of the first file
        with a failing header or content CRC, or None if all files were okay.
        Raises EncryptedArchiveError if an archive member is encrypted but no
        password was provided.
        """
        for ai in self.__file_aceinfos:
            if not self.test(ai, pwd=pwd):
                return ai.filename
        return None

    def dumpheaders(self, file=sys.stdout):
        """
        Dump all ACE file format headers to *file*.
        """
        for h in self.__all_headers:
            print(h, file=file)

    def is_solid(self):
        """
        Return True iff archive is a solid archive, i.e. iff the archive
        members are linked to each other by sharing the same dictionary.
        """
        return self.__main_header.flag(Header.FLAG_SOLID)

    @property
    def filename(self):
        """
        ACE archive filename.  This is not a property of the archive but rather
        just the filename passed to the AceFile constructor.
        """
        return self.__filename

    @property
    def cversion(self):
        """
        ACE creator version, version of ACE format used to create the archive.
        """
        return self.__main_header.cversion

    @property
    def eversion(self):
        """
        ACE extractor version, version of ACE format handler needed to extract.
        """
        return self.__main_header.eversion

    @property
    def mtime(self):
        """
        Archive modification timestamp as datetime object.
        """
        return _dt_fromdos(self.__main_header.datetime)

    @property
    def comment(self):
        """
        ACE archive level comment.
        """
        return self.__main_header.comment

    @property
    def advert(self):
        """
        ACE archive level advert string.
        """
        return self.__main_header.advert

    @staticmethod
    def _decompress_comment(buf):
        """
        Decompress an ACE MAIN or FILE comment.  These are compressed using
        Huffman coding plus a simple copy mechanism.
        """
        bs = BitStream(io.BytesIO(buf), len(buf))
        want_size = bs.read_bits(15)
        huff_syms, huff_widths = Huffman.read_widths(bs,
                                                     LZ77.MAXCODEWIDTH,
                                                     LZ77.NUMMAINCODES)
        comment = []
        htab = [0] * 511
        while len(comment) < want_size:
            if len(comment) > 1:
                hval = comment[-1] + comment[-2]
                source_pos = htab[hval]
                htab[hval] = len(comment)
            else:
                source_pos = 0

            code = huff_syms[bs.peek_bits(LZ77.MAXCODEWIDTH)]
            bs.skip_bits(huff_widths[code])

            if code < 256:
                comment.append(code)
            else:
                for i in range(code - 256 + 2):
                    comment.append(comment[source_pos + i])
        return bytes(comment)

    def _parse_headers(self, search):
        """
        Parse ACE headers from self.__file.  If *search* is > 0, search for
        the magic bytes in the first *search* bytes of the file.
        Raises MainHeaderNotFoundError if the main header could not be located.
        Raises other exceptions if parsing fails for other reasons.
        On success, loads all the parsed headers into
        self.__main_header, self.__file_headers and/or self.__all_headers.
        """
        self.__file.seek(0, 0)
        buf = self.__file.read(512)
        found_at_start = False
        if buf[7:14] == MainHeader.MAGIC:
            self.__file.seek(0, 0)
            try:
                self._parse_header()
                found_at_start = True
            except (CorruptedArchiveError, TruncatedArchiveError):
                pass
        if not found_at_start:
            if search == 0:
                raise MainHeaderNotFoundError()
            self.__file.seek(0, 0)
            buf = self.__file.read(search)
            magicpos = 7
            while magicpos < search:
                magicpos = buf.find(MainHeader.MAGIC, magicpos + 1, search)
                if magicpos == -1:
                    raise MainHeaderNotFoundError()
                self.__file.seek(magicpos - 7, 0)
                try:
                    self._parse_header()
                    break
                except (CorruptedArchiveError, TruncatedArchiveError):
                    continue
        while self.__file.tell() < self.__filesize:
            self._parse_header()

    def _parse_header(self):
        """
        Parse a single header from self.__file at the current file position.
        Raises CorruptedArchiveError or TruncatedArchiveError if the header
        cannot be parsed.  Guarantees that no data is written to object state
        if an exception is thrown, otherwise the header is added to
        self.__main_header, self.__file_headers and/or self.__all_headers.
        """
        buf = self.__file.read(4)
        if len(buf) < 4:
            raise TruncatedArchiveError()
        hcrc, hsize = struct.unpack('<HH', buf)
        buf = self.__file.read(hsize)
        if len(buf) < hsize:
            raise TruncatedArchiveError()
        if ace_crc16(buf) != hcrc:
            raise CorruptedArchiveError()
        htype, hflags = struct.unpack('<BH', buf[0:3])
        i = 3

        if htype == Header.TYPE_MAIN:
            header = MainHeader(hcrc, hsize, htype, hflags)
            if header.flag(Header.FLAG_ADDSIZE):
                raise CorruptedArchiveError()
            header.magic = buf[3:10]
            if header.magic != MainHeader.MAGIC:
                raise CorruptedArchiveError()
            header.eversion, \
            header.cversion, \
            header.host, \
            header.volume, \
            header.datetime = struct.unpack('<BBBBL', buf[10:18])
            header.reserved1 = buf[18:26]
            i = 26
            if header.flag(Header.FLAG_ADVERT):
                if i + 1 > len(buf):
                    raise CorruptedArchiveError()
                avsz, = struct.unpack('<B', buf[i:i+1])
                i += 1
                if i + avsz > len(buf):
                    raise CorruptedArchiveError()
                header.advert = buf[i:i+avsz].decode('utf-8', errors='replace')
                i += avsz
            if header.flag(Header.FLAG_COMMENT):
                if i + 2 > len(buf):
                    raise CorruptedArchiveError()
                cmsz, = struct.unpack('<H', buf[i:i+2])
                i += 2
                if i + cmsz > len(buf):
                    raise CorruptedArchiveError()
                comment = self._decompress_comment(buf[i:i+cmsz])
                header.comment = comment.decode('utf-8', errors='replace')
                i += cmsz
            header.reserved2 = buf[i:]
            if self.__main_header != None:
                raise CorruptedArchiveError()
            self.__main_header = header

        elif htype in [Header.TYPE_FILE32, Header.TYPE_FILE64]:
            header = FileHeader(hcrc, hsize, htype, hflags)
            if not header.flag(Header.FLAG_ADDSIZE):
                raise CorruptedArchiveError()
            if header.flag(Header.FLAG_64BIT):
                if htype != Header.TYPE_FILE64:
                    raise CorruptedArchiveError()
                if i + 16 > len(buf):
                    raise CorruptedArchiveError()
                header.packsize, \
                header.origsize, = struct.unpack('<QQ', buf[i:i+16])
                i += 16
            else:
                if htype != Header.TYPE_FILE32:
                    raise CorruptedArchiveError()
                if i + 8 > len(buf):
                    raise CorruptedArchiveError()
                header.packsize, \
                header.origsize, = struct.unpack('<LL', buf[i:i+8])
                i += 8
            if i + 20 > len(buf):
                raise CorruptedArchiveError()
            header.datetime, \
            header.attribs, \
            header.crc32, \
            header.comptype, \
            header.compqual, \
            header.params, \
            header.reserved1, \
            fnsz = struct.unpack('<LLLBBHHH', buf[i:i+20])
            i += 20
            if i + fnsz > len(buf):
                raise CorruptedArchiveError()
            header.filename = buf[i:i+fnsz].decode('utf-8', errors='replace')
            i += fnsz
            if header.flag(Header.FLAG_COMMENT):
                if i + 2 > len(buf):
                    raise CorruptedArchiveError()
                cmsz, = struct.unpack('<H', buf[i:i+2])
                i += 2
                if i + cmsz > len(buf):
                    raise CorruptedArchiveError()
                comment = self._decompress_comment(buf[i:i+cmsz])
                header.comment = comment.decode('utf-8', errors='replace')
                i += cmsz
            header.reserved2 = buf[i:]
            header.dataoffset = self.__file.tell()
            self.__file_headers.append(header)
            self.__file.seek(header.packsize, 1)

        else:
            header = UnknownHeader(hcrc, hsize, htype, hflags)
            addsz = 0
            if header.flag(Header.FLAG_ADDSIZE):
                if header.flag(Header.FLAG_64BIT):
                    if i + 8 > len(buf):
                        raise CorruptedArchiveError()
                    addsz, = struct.unpack('<Q', buf[i:i+8])
                else:
                    if i + 4 > len(buf):
                        raise CorruptedArchiveError()
                    addsz, = struct.unpack('<L', buf[i:i+4])
            self.__file.seek(addsz, 1)

        self.__all_headers.append(header)



def is_acefile(file, search=524288):
    """
    Return True if *file* refers to an ACE archive by filename or seekable
    file-like object.  If *search* is > 0, search for the magic bytes in the
    first *search* bytes of the file.
    """
    try:
        ace = open(file, search)
        ace.close()
        return True
    except AceError:
        return False



builtin_open = open
open = AceFile.open



def unace():
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="""
            Read from ACE format archives in pure python.
            """)

    parser.add_argument('archive', type=str,
            help='archive to read from')
    parser.add_argument('file', nargs='*', type=str,
            help='file(s) in archive to operate on, default all')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--extract', '-x', default='extract',
            action='store_const', dest='mode', const='extract',
            help='extract files in archive (default)')
    group.add_argument('--list', '-l',
            action='store_const', dest='mode', const='list',
            help='list files in archive')
    group.add_argument('--test', '-t',
            action='store_const', dest='mode', const='test',
            help='test archive integrity')
    group.add_argument('--headers',
            action='store_const', dest='mode', const='headers',
            help='dump archive headers')
    group.add_argument('--selftest',
            action='store_const', dest='mode', const='selftest',
            help='implementation selftest')

    parser.add_argument('--basedir', type=str, default='.',
            help='base directory for extraction')
    parser.add_argument('--password', '-p', type=str,
            help='password for decryption')
    parser.add_argument('-y', '--yes', action='store_true',
            help='assume yes to all questions')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='be more verbose')

    # not implemented arguments that other unace implementations have:
    # --(no-)full-path              always full path extraction
    # --(no-)show-comments          show comments iff verbose
    # --(no-)overwrite-files        always overwrite files
    # --(no-)full-path-matching     always full path matching
    # --exclude(-list)              feature not implemented

    args = parser.parse_args()

    if args.mode != 'extract' and len(args.file) > 0:
        eprint("%s: error: not extracting, but files were specified" %
               os.path.basename(sys.argv[0]))
        sys.exit(1)

    if args.archive == '-':
        if sys.stdin.seekable():
            archive = sys.stdin
        else:
            archive = io.BytesIO(sys.stdin.buffer.read())
    else:
        archive = args.archive

    with open(archive) as f:
        if args.verbose:
            eprint("processing archive %s" % f.filename)
            eprint("created on %s with version %i (extract with %i+)" % (
                f.mtime.strftime('%Y-%m-%d %H:%M:%S'), f.cversion, f.eversion))
            if f.advert:
                eprint("by %s" % f.advert)
            if f.comment:
                eprint(asciibox(f.comment, title='archive comment'))

        if args.mode == 'extract':
            failed = 0
            password = args.password
            if args.file:
                members = [f.getmember(m) for m in args.file]
            else:
                members = f.getmembers()
            for ai in members:
                if ai.is_enc() and password == None and not args.yes:
                    try:
                        password = getpass.getpass("%s password: " % \
                                                    ai.filename)
                    except EOFError:
                        password = None
                while True:
                    try:
                        f.extract(ai, path=args.basedir, pwd=password)
                        if args.verbose:
                            eprint("%s" % ai.filename)
                        break
                    except EncryptedArchiveError:
                        if args.verbose or args.yes or not password:
                            eprint("%s failed to decrypt" % ai.filename)
                        if args.yes or not password:
                            failed += 1
                            break
                        try:
                            password = getpass.getpass("%s password: " % \
                                                        ai.filename)
                        except EOFError:
                            password = ''
                        if password == '':
                            password = args.password
                            eprint("%s skipped" % ai.filename)
                            failed += 1
                            break
                    except AceError:
                        eprint("%s failed to extract" % ai.filename)
                        failed += 1
                        break
                if f.is_solid() and failed > 0:
                    eprint("error extracting from solid archive, aborting")
                    sys.exit(1)
                if args.verbose and ai.comment:
                    eprint(asciibox(ai.comment, title='file comment'))
            if failed > 0:
                sys.exit(1)

        elif args.mode == 'list':
            if args.verbose:
                eprint("type    size     packed   rel  timestamp            filename")
                count = count_size = count_packsize = 0
                for ai in f.getmembers():
                    if ai.is_reg():
                        t = 'f'
                    elif ai.is_dir():
                        t = 'd'
                    else:
                        t = '?'
                    if ai.is_enc():
                        e = '+'
                    else:
                        e = ' '
                    if ai.size > 0:
                        ratio = (100 * ai.packsize) // ai.size
                    else:
                        ratio = 100
                    print("%s%s %9i  %9i  %3i%%  %s  %s" % (
                        t, e,
                        ai.size,
                        ai.packsize,
                        ratio,
                        ai.mtime.strftime('%Y-%m-%d %H:%M:%S'),
                        ai.filename))
                    if ai.comment:
                        eprint(asciibox(ai.comment, title='file comment'))
                    count_size += ai.size
                    count_packsize += ai.packsize
                    count += 1
                eprint("total %i members, %i bytes, %i bytes compressed" % (
                       count, count_size, count_packsize))
            else:
                for fn in f.getnames():
                    print("%s" % fn)

        elif args.mode == 'test':
            failed = 0
            ok = 0
            password = args.password
            for ai in f.getmembers():
                if f.is_solid() and failed > 0:
                    print("failure  %s" % ai.filename)
                    failed += 1
                    continue
                if ai.is_enc() and password == None and not args.yes:
                    try:
                        password = getpass.getpass("%s password: " % \
                                                    ai.filename)
                    except EOFError:
                        password = None
                while True:
                    try:
                        if f.test(ai, pwd=password):
                            print("success  %s" % ai.filename)
                            ok += 1
                        else:
                            print("failure  %s" % ai.filename)
                            failed += 1
                        break
                    except EncryptedArchiveError:
                        if args.yes or not password:
                            print("needpwd  %s" % ai.filename)
                            failed += 1
                            break
                        eprint("last used password failed")
                        try:
                            password = getpass.getpass("%s password: " % \
                                                        ai.filename)
                        except EOFError:
                            password = ''
                        if password == '':
                            password = args.password
                            print("needpwd  %s" % ai.filename)
                            failed += 1
                            break
                if args.verbose and ai.comment:
                    eprint(asciibox(ai.comment, title='file comment'))
            eprint("total %i tested, %i ok, %i failed" % (
                   ok + failed, ok, failed))
            if failed > 0:
                sys.exit(1)

        elif args.mode == 'headers':
            f.dumpheaders()

        elif args.mode == 'selftest':
            eprint('dumpheaders():')
            f.dumpheaders()
            eprint('-' * 78)
            eprint('getnames():')
            for fn in f.getnames():
                eprint("%s" % fn)
            eprint('-' * 78)
            eprint('testall():')
            rv = f.testall()
            if rv != None:
                eprint("Test failed: member %s is corrupted" % rv)
                sys.exit(1)
            eprint('-' * 78)
            eprint('test() in order:')
            for member in f.getmembers():
                if f.test(member):
                    eprint("%s: CRC OK" % member.filename)
                else:
                    eprint("%s: CRC FAILED" % member.filename)
                    sys.exit(1)
            eprint('-' * 78)
            eprint('test() in reverse order:')
            for member in reversed(f.getmembers()):
                if f.test(member):
                    eprint("%s: CRC OK" % member.filename)
                else:
                    eprint("%s: CRC FAILED" % member.filename)
                    sys.exit(1)
        # end of with open
    sys.exit(0)



if __name__ == '__main__':
    unace()

