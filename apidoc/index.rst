|project| |version| API Documentation
=====================================

.. toctree::
   :maxdepth: 3

.. automodule:: acefile

Using the API
-------------

Typical use of :mod:`acefile` has the following structure:

.. code:: python

    import acefile
    with acefile.open('example.ace') as f:
        # operations on AceArchive f
        for member in f:
            # operations on AceArchive f and each AceMember member

See :class:`acefile.AceArchive` and :class:`acefile.AceMember` for the
complete descriptions of the methods supported by these two classes.

Functions
~~~~~~~~~

.. autofunction:: is_acefile

.. autofunction:: open(file, mode='r', \*, search=524288)

AceArchive Class
~~~~~~~~~~~~~~~~

.. autoclass:: AceArchive
    :members:

AceMember Class
~~~~~~~~~~~~~~~

.. autoclass:: AceMember()
    :members:

Constants
~~~~~~~~~

.. autodata:: COMP_STORED
    :annotation:

.. autodata:: COMP_LZ77
    :annotation:

.. autodata:: COMP_BLOCKED
    :annotation:

.. autodata:: QUAL_NONE
    :annotation:

.. autodata:: QUAL_FASTEST
    :annotation:

.. autodata:: QUAL_FAST
    :annotation:

.. autodata:: QUAL_NORMAL
    :annotation:

.. autodata:: QUAL_GOOD
    :annotation:

.. autodata:: QUAL_BEST
    :annotation:

Exceptions
~~~~~~~~~~

.. autoexception:: AceError

.. autoexception:: CorruptedArchiveError
    :show-inheritance:

.. autoexception:: EncryptedArchiveError
    :show-inheritance:

.. autoexception:: MainHeaderNotFoundError
    :show-inheritance:

.. autoexception:: MultiVolumeArchiveError
    :show-inheritance:

.. autoexception:: UnknownCompressionMethodError
    :show-inheritance:

Examples
--------

Extract all files in the archive, with directories, to current working dir:

.. code:: python

    import acefile
    with acefile.open('example.ace') as f:
        f.extractall()

Walk all files in the archive and test each one of them:

.. code:: python

    import acefile
    with acefile.open('example.ace') as f:
        for member in f.getmembers():
            if f.is_dir():
                continue
            if f.test(member):
                print("CRC OK:     %s" % member.filename)
            else:
                print("CRC FAIL:   %s" % member.filename)

In-memory decompression of a specific archive member:

.. code:: python

    import acefile
    import io

    filelike = io.BytesIO(b'\x73\x83\x31\x00\x00\x00\x90**ACE**\x14\x14' ...)
    with acefile.open(filelike) as f:
        data = f.read('example.txt')

Handle archives potentially containing large members in chunks to avoid fully
reading them into memory:

.. code:: python

    import acefile

    with acefile.open('large.ace') as fi:
        with open('large.iso', 'wb') as fo:
            for block in fi.readblocks('large.iso'):
                fo.write(block)

ACE File Format
---------------

File Structure
~~~~~~~~~~~~~~

ACE archives are a series of headers and associated data.  The first header is
called ``MAIN`` header; it contains the magic bytes ``**ACE**`` at offset +7
and describes the archive volume.  Subsequent headers are either ``FILE`` or
``RECOVERY`` headers.  ``FILE`` headers describe archive members and preceed
the compressed data bytes, while ``RECOVERY`` headers contain error correction
data.  Originally, in ACE 1.0, all headers used 32 bit length fields.  With ACE
2.0, alternative 64 bit versions of these headers were introduced to support
files larger than 2 GB.

In multi-volume archives, each volume begins with a ``MAIN`` header that
carries a volume number.  When archive members span multiple volumes, each
segment has it's own ``FILE`` header.

Archives can have a main comment and each archive member can have a file
comment.  Additionally, archives can have an advert string, which is used by
unregistered versions of the ACE compressor to signal that the archive was
created using an unregistered version by setting it to ``*UNREGISTERED
VERSION*``.


Integrity Checks
~~~~~~~~~~~~~~~~

Each header contains a 16 bit checksum over the header bytes.  Each archive
member has a 32 bit checksum over the decompressed bytes.  ACE uses an bitwise
inverted CRC-32 checksum as the 32 bit checksum, and a truncated version of
that for the 16 bit checksum.


Compression Methods
~~~~~~~~~~~~~~~~~~~

Archive members are compressed using one of the following methods:

**stored**
    Data is stored as-is without any compression applied.

**LZ77**
    ACE 1.0 plain LZ77 compression over a Huffman-encoded symbol stream.

**blocked**
    ACE 2.0 blocked mode compresses data in separate blocks, each block using
    one of the following submodes with different lossless compression
    techniques.

    **LZ77**
        Plain LZ77 over a Huffman-encoded symbol stream.

    **EXE**
        LZ77 over Huffman with a preprocessor that adjusts target addresses of
        x86 JMP and CALL instructions in order to achieve a higher LZ77
        compression ratio for executables.

    **DELTA**
        LZ77 over Huffman with a preprocessor that rearranges chunks of data
        and calculates differences between byte values, resulting in a higher
        LZ77 compression ratio for some inputs.

    **SOUND**
        Multi-channel audio predictor over Huffman-encoding, resulting in a
        higher compression ratio for uncompressed mono/stereo 8/16 bit sound
        data.

    **PIC**
        Two-dimensional pixel colour predictor over Huffman-encoding, resulting
        in a higher compression ratio for uncompressed picture data.

Comments are compressed using LZP over a Huffman-encoded symbol stream.  Advert
strings and other header information are uncompressed.


Encryption
~~~~~~~~~~

Optional encryption is applied to the compressed data stream after compression.
The user-supplied password of up to 50 characters is transformed into a 160 bit
Blowfish encryption key using a single application of SHA-1, albeit using
non-standard block padding.  Blowfish is applied in CBC mode using a constant
zero IV to each archive member separately.

