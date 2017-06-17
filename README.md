# acefile - read from ACE format archives in pure python
Copyright (C) 2017, [Daniel Roethlisberger](//daniel.roe.ch/).  
https://www.roe.ch/acefile


## Synopsis

    pip install acefile

    # python library
    import acefile
    with acefile.open("example.ace") as f:
        f.extractall()

    # unace utility
    acefile-unace -x example.ace


## Overview

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


## Requirements

Python 3.  No other dependencies.


## Installation

    pip install acefile


## Library usage

Extract all files in the archive, with directories, to current working dir:

    import acefile
    with acefile.open("example.ace") as f:
        f.extractall()

Walk all files in the archive and test each one of them:

    import acefile
    with acefile.open("example.ace") as f:
        for ai in f.getmembers():
            if f.is_dir():
                continue
            if f.test(ai):
                print("CRC OK:    %s" % ai.filename)
            else:
                print("CRC FAIL:  %s" % ai.filename)

In-memory decompression of a specific archive member:

    import acefile
    import io

    filelike = io.BytesIO(b'\x73\x83\x31\x00\x00\x00\x90**ACE**\x14\x14' ...)
    with acefile.open(filelike) as f:
        data = f.read('example.txt')

Check the source for more functionality.


## Utility usage

Extract all files in the archive, with directories, to current working dir:

    acefile-unace -x example.ace

Test all files in the archive:

    acefile-unace -t example.ace

List archive contents, verbosely:

    acefile-unace -lv example.ace

Check usage for more functionality:

    acefile-unace -h


## Credits

Marcel Lemke for designing the ACE archive format and ACE compression and
decompression algorithms.

