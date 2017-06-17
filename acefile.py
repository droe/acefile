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
including the EXE, DIFF, PIC and SOUND modes of ACE 2.0.  Some ACE features
are not fully implemented, most notably password protection, multivolume
support and comments decompression.

This is an implementation from scratch, based on the 1998 document titled
"Technical information of the archiver ACE v1.2" by Marcel Lemke, using
unace 2.5 and WinAce 2.69 by Marcel Lemke as reference implementations.
"""

__version__     = '0.2.1'
__author__      = 'Daniel Roethlisberger'
__email__       = 'daniel@roe.ch'
__copyright__   = 'Copyright 2017, Daniel Roethlisberger'
__credits__     = ['Marcel Lemke']
__license__     = 'BSD'
__url__         = 'https://www.roe.ch/acefile'

__all__         = ['AceFile', 'AceInfo', 'is_acefile', 'AceError']

# TODO
# -   Decompress comments
# -   Password protection
# -   Seek into first N bytes of files as per specs
# -   Look into performance bottlenecks

import datetime
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
            if hval & 1 == 1:
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

    def __add__(self, buf):
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
        Behaviour is undefined for start < 0, length < 0 or start + length > 8.
        """
        #assert start >= 0 and length >= 0 and start + length <= 8
        mask = ((0xFF << (8 - length)) & 0xFF) >> start
        return (value & mask) >> (8 - length - start)

    def __init__(self, f, size):
        """
        Initialize BitStream reading from file-like object *f* a maximum of
        *size* bytes, after which there is a maximum of 32 bits zero padding.
        """
        assert size % 4 == 0
        self.__file = f
        self.__file_remaining = size    # in bytes
        self.__buf = []
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
        assert len(tmpbuf) == amount
        self.__file_remaining -= len(tmpbuf)

        newbuf = self.__buf[-4:]
        for i in range(0, len(tmpbuf), 4):
            newbuf.append(tmpbuf[i+3])
            newbuf.append(tmpbuf[i+2])
            newbuf.append(tmpbuf[i+1])
            newbuf.append(tmpbuf[i])
        if len(tmpbuf) < FILE_BLOCKSIZE:
            newbuf.extend([0] * 4)
        if self.__pos > 0:
            self.__pos -= (self.__len - 32)
        self.__buf = newbuf
        self.__len = 8 * len(newbuf)

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
        peeked = min(bits, 8 - (self.__pos % 8))
        res = self._getbits(self.__buf[self.__pos // 8],
                            self.__pos % 8, peeked)
        while bits - peeked >= 8:
            res <<= 8
            res += self.__buf[(self.__pos + peeked) // 8]
            peeked += 8
        if bits - peeked > 0:
            res <<= bits - peeked
            res += self._getbits(self.__buf[(self.__pos + peeked) // 8],
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



class Huffman:
    """
    Huffman decoder engine.
    """
    MAXWIDTHSVDWD       = 7
    MAXWIDTHTOSAVE      = 15

    def __init__(self):
        pass

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

    # quasi-static
    def _make_codes(self, max_width, count, widths, codes):
        frequencies = list(widths)
        elements    = list(range(len(widths)))

        self._quicksort(frequencies, elements, count)

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

    # quasi-static
    def read_widths(self, bs, max_width, num_codes):
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

        save_widths = [0] * Huffman.MAXWIDTHTOSAVE
        for i in range(upper_width + 1):
            save_widths[i] = bs.read_bits(3)
        self._make_codes(Huffman.MAXWIDTHSVDWD, upper_width + 1, save_widths, codes)

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

        self._make_codes(max_width, num_widths, widths, codes)
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
        self.__huff = Huffman()
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
        main_syms, main_widths = self.__huff.read_widths(bs,
                                                         LZ77.MAXCODEWIDTH,
                                                         LZ77.NUMMAINCODES)
        len_syms,  len_widths  = self.__huff.read_widths(bs,
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
        self.__huff = Huffman()
        self.quantizer = [None] * 256
        self.quantizer[0] = 0
        for i in range(1, 129):
            self.quantizer[256 - i] = self.quantizer[i] = int(math.log2(i)) + 1
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
                    self.__huff.read_widths(bs, Sound.MAXCODEWIDTH,
                                                Sound.NUMCODES)
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
        self.__huff = Huffman()

        self.__bit_width = [0] * LZ77.MAXDIST2
        self.__bit_width[0] = 0
        for i in range(1, LZ77.MAXDIST2):
            self.__bit_width[i] = int(math.log2(i)) + 1
        self.__dif_bit_width = [0] * 256
        for i in range(0, 128):
            self.__dif_bit_width[i] = self.__bit_width[2 * i]
        for i in range(-128, 0):
            self.__dif_bit_width[i] = self.__bit_width[- 2 * i - 1]

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
        epsilon = bs.golomb_rice(self.__bit_width[r], signed=True)
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
        self.__huff = Huffman()
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
    #MAGIC_SEARCH        = 1024*512

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

    # only ATTR_DIR seems to be reliable; are the semantics platform-dependent?
    ATTR_DIR            = 0x00000010
    ATTR_REG            = 0x00000020
    ATTR_STRINGS        = ('1', '2', '4', '8', 'DIR', 'REG')

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
    pass

class TruncatedArchiveError(AceError):
    pass

class CorruptedArchiveError(AceError):
    pass

class UnknownAttributesError(AceError):
    pass

class UnknownMethodError(AceError):
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

    def is_dir(self):
        """
        True iff AceInfo object refers to a directory.
        """
        return self.attribs & Header.ATTR_DIR == Header.ATTR_DIR

    def is_reg(self):
        """
        True iff AceInfo object refers to a regular file.
        """
        # ATTR_REG seems to be unreliable, so for now, we're just inverting
        # is_dir() instead of checking for specific attribute bits.
        #return self.attribs & Header.ATTR_REG == Header.ATTR_REG
        return not self.is_dir()



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

    def __init__(self, file, mode='r'):
        """
        Open archive from file, which is either a filename or seekable
        file-like object.  Only mode 'r' is implemented.
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
        self._parse_headers()
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

    def getmember(self, name):
        """
        Return an AceInfo object corresponding to archive member *name*.
        Raise KeyError if *name* is not found in archive.
        If the member name occurs multiple times, the last one is returned.
        """
        match = None
        for ai in self.__file_aceinfos:
            if ai.filename == name:
                match = ai
        if match == None:
            raise KeyError()
        return match

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

    def _get_file_idx(self, member):
        """
        Return index into self.__file_headers and self.__file_aceinfos
        corresponding to *member*, which can be an AceInfo object, a name
        or an index into the archive member list.
        """
        if isinstance(member, int):
            return member
        elif isinstance(member, str):
            return self.getmember(member)._idx
        elif isinstance(member, AceInfo):
            return member._idx
        else:
            raise TypeError()

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
        if hdr.attrib(Header.ATTR_DIR):
            try:
                os.mkdir(fn)
            except FileExistsError:
                pass
        # ATTR_REG is unreliable
        #elif hdr.attrib(Header.ATTR_REG):
        else:
            basedir = os.path.dirname(fn)
            if basedir != '':
                os.makedirs(basedir, exist_ok=True)
            with builtin_open(fn, 'wb') as f:
                for buf in self.readblocks(ai, pwd=pwd):
                    f.write(buf)
        #else:
        #    raise UnknownAttributesError()

    def extractall(self, path=None, members=None, pwd=None):
        """
        Extract *members* or all members from archive to *path* or the current
        working directory.  Members can contain AceInfo objects, member names
        or indexes into the archive member list.
        """
        if members == None or members == []:
            members = self.__file_aceinfos
        else:
            if self.__main_header.flag(Header.FLAG_SOLID):
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
        if pwd:
            raise NotImplementedError()

        idx = self._get_file_idx(member)
        ai = self.__file_aceinfos[idx]
        hdr = self.__file_headers[idx]

        # Ensure the LZ77 state corresponds to the state after extracting the
        # previous file by re-starting extraction from the beginning or the
        # last extracted file.
        if self.__main_header.flag(Header.FLAG_SOLID) and \
                self.__next_read_idx != idx:
            if self.__next_read_idx < idx:
                restart_idx = self.__next_read_idx
            else:
                restart_idx = self.__next_read_idx = 0
            for i in range(restart_idx, idx):
                if not self.test(self.__file_aceinfos[i]):
                    raise CorruptedArchiveError()

        if hdr.flag(Header.FLAG_PASSWORD):
            raise NotImplementedError()

        if (not hdr.attrib(Header.ATTR_DIR)) and hdr.origsize > 0:
            if hdr.comptype == Header.COMP_STORE:
                decompressor = self.__ace.decompress_stored
            elif hdr.comptype == Header.COMP_LZ77:
                decompressor = self.__ace.decompress_lz77
            elif hdr.comptype == Header.COMP_BLOCKED:
                decompressor = self.__ace.decompress_blocked
            else:
                raise UnknownMethodError()

            crc = AceCRC32()
            self.__file.seek(hdr.dataoffset, 0)
            for block in decompressor(self.__file, hdr.packsize, hdr.origsize,
                                      hdr.params):
                crc += block
                yield block
            if crc != hdr.crc32:
                raise CorruptedArchiveError()

        self.__next_read_idx += 1

    def test(self, member, pwd=None):
        """
        Read a file from the archive.  Returns False if any corruption was
        found, True if the header and decompression was okay.
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
        except AceError:
            return False

    def testall(self, pwd=None):
        """
        Read all the files in the archive.  Returns the name of the first file
        with a failing header or content CRC, or None if all files were okay.
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

    def _parse_headers(self):
        # This assumes no garbage before and after the archive
        self.__file.seek(0, 0)
        while self.__file.tell() < self.__filesize:
            self._parse_header()

    def _parse_header(self):
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
                # FIXME decompress comment
                header.comment = buf[i:i+cmsz].decode('utf-8', errors='replace')
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
                # FIXME decompress comment
                header.comment = buf[i:i+cmsz].decode('utf-8', errors='replace')
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



def is_acefile(file):
    """
    Return True if file refers to an ACE archive by filename or seekable
    file-like object.
    """
    try:
        ace = open(file)
        ace.close()
        return True
    except AceError:
        return False



builtin_open = open
open = AceFile.open



def unace():
    import argparse
    import io

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
            help='implementation selftest')
    group.add_argument('--selftest',
            action='store_const', dest='mode', const='selftest',
            help='implementation selftest')

    parser.add_argument('--basedir', type=str, default='.',
            help='base directory for extraction')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='be more verbose')

    # not implemented arguments that other unace implementations have:
    # --(no-)full-path              always full path extraction
    # --(no-)show-comments          never show comments
    # --(no-)overwrite-files        always overwrite files
    # --(no-)full-path-matching     always full path matching
    # --exclude(-list)              feature not implemented
    # --password                    feature not implemented
    # --yes                         not applicable

    args = parser.parse_args()

    if args.mode == 'list' and len(args.file) > 0:
        eprint("%s: error: cannot list only a subset of files in archive" %
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
                eprint(f.comment)

        if args.mode == 'extract':
            f.extractall(path=args.basedir, members=args.file)

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
                    print("%s  %9i  %9i  %3i%%  %s  %s" % (
                        t,
                        ai.size,
                        ai.packsize,
                        (100 * ai.packsize) // ai.size,
                        ai.mtime.strftime('%Y-%m-%d %H:%M:%S'),
                        ai.filename))
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
            for member in f.getmembers():
                if f.test(member):
                    print("success  %s" % member.filename)
                    ok += 1
                else:
                    print("failure  %s" % member.filename)
                    failed += 1
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

