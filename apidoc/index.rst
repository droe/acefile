API Documentation
=================

.. toctree::
   :maxdepth: 2

Synopsis
--------

.. code:: python

    import acefile
    with acefile.open('example.ace') as f:
        for member in f:
            f.extract(member)

Description
-----------

.. automodule:: acefile

Functions
---------

.. autofunction:: is_acefile

.. autofunction:: open(file, mode='r', \*, search=524288)

AceArchive Class
----------------

.. autoclass:: AceArchive
    :members:

AceMember Class
---------------

.. autoclass:: AceMember()
    :members:

Exceptions
----------

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


