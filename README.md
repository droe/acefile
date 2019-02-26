# acefile - read/test/extract ACE 1.0 and 2.0 archives in pure python
Copyright (C) 2017-2019, [Daniel Roethlisberger](//daniel.roe.ch/).  
https://www.roe.ch/acefile  


## Synopsis

    pip install acefile

    # python library
    import acefile
    with acefile.open('example.ace') as f:
        f.extractall()

    # unace utility
    acefile-unace -x example.ace


## Overview

This single-file, pure python 3, no-dependencies implementation is intended
to be used as a library, but also provides a stand-alone unace utility.
As mostly pure-python implementation, it is significantly slower than
native implementations, but more robust against vulnerabilities.

This implementation supports up to version 2.0 of the ACE archive format,
including the EXE, DELTA, PIC and SOUND modes of ACE 2.0, password protected
archives and multi-volume archives.  It does not support writing to archives.
It is an implementation from scratch, based on the 1998 document titled
"Technical information of the archiver ACE v1.2" by Marcel Lemke, using
unace 2.5 and WinAce 2.69 by Marcel Lemke as reference implementations.

For more information, API documentation, source code, packages and release
notifications, refer to:

- https://www.roe.ch/acefile
- https://apidoc.roe.ch/acefile
- https://github.com/droe/acefile
- https://pypi.python.org/pypi/acefile
- https://twitter.com/droethlisberger


## Requirements

Python 3.  No other dependencies.


## Installation

    pip install acefile

The `acefile` package includes an optional `acebitstream` module that
implements the bit stream class in c, resulting in a 50% speedup.
It is automatically used wherever it builds cleanly, but is not required.


## Library usage examples

Extract all files in the archive, with directories, to current working dir:

    import acefile
    with acefile.open('example.ace') as f:
        f.extractall()

Walk all files in the archive and test each one of them:

    import acefile
    with acefile.open('example.ace') as f:
        for member in f:
            if member.is_dir():
                continue
            if f.test(member):
                print("CRC OK:     %s" % member.filename)
            else:
                print("CRC FAIL:   %s" % member.filename)

In-memory decompression of a specific archive member:

    import acefile
    import io

    filelike = io.BytesIO(b'\x73\x83\x31\x00\x00\x00\x90**ACE**\x14\x14' ...)
    with acefile.open(filelike) as f:
        data = f.read('example.txt')

Handle archives potentially containing large members in chunks to avoid fully
reading them into memory:

    import acefile

    with acefile.open('large.ace') as fi:
        with open('large.iso', 'wb') as fo:
            for block in fi.readblocks('large.iso'):
                fo.write(block)

Check the [API documentation](https://apidoc.roe.ch/acefile) for a complete
description of the API.


## Utility usage examples

Extract all files in the archive, with directories, to current working dir:

    acefile-unace -x example.ace

Test all files in the archive, verbosely:

    acefile-unace -tv example.ace

List archive contents, verbosely:

    acefile-unace -lv example.ace

Check usage for more functionality:

    acefile-unace -h


## Credits

Marcel Lemke for designing the ACE archive format and ACE compression and
decompression algorithms.

