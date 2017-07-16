### acefile 0.6.1 2017-07-16

-   Truncate password to 50 bytes for 1:1 compatibility with official unace.
-   40% performance increase of LZ77 decompression by reading LZ77 symbols as
    needed instead of pre-loading whole blocks.
-   Extended API documentation with high-level file format description.


### acefile 0.6.0 2017-07-15

-   Library API overhaul towards a stable API:
    -   Add AceArchive.is_locked() for testing if an archive is locked.
    -   Add constants for compression types and quality.
    -   Replace AceArchive.mtime and AceMember.mtime with .datetime in order
        to avoid confusion as ACE does not have separate modification and
        creation times.
    -   Replace AceMember.orig_filename with AceMember.raw_filename and
        change type from str to bytes.
    -   Replace AceMember.params with decoded AceMember.dicsizebits and
        AceMember.dicsize, holding the decoded dictionary size as power of
        two and as effective number of literals, respectively.
    -   Replace UnknownMethodError with UnknownCompressionMethodError.
    -   Remove the AceFile alias of the AceArchive class.
    -   Remove AceArchive.open().
    -   Remove TruncatedArchiveError; CorruptedArchiveError is used instead.
-   Ensure all open files are closed on exceptions during object creation.
-   Roughly 10% performance increase by constructing non-standard ACE CRC-32
    from python standard library zlib.crc32 instead of using a pure python
    CRC implementation.
-   Show more metadata in CLI --verbose archive info and --list.
-   Generate API documentation.


### acefile 0.5.2 2017-07-03

-   Renamed AceFile to AceArchive, but AceFile is still available as an alias.
-   Hidden AceInfo class from the API, it is still there but not in __all__.
-   Added all exceptions to the API.
-   Improved filename sanitization.


### acefile 0.5.1 2017-07-02

-   Fix regression that broke extraction when directly writing the yielded
    chunks to files.


### acefile 0.5.0 2017-07-01

-   Add multi-volume archive support.
-   All optional function arguments in the library API must now be passed in
    keyword syntax, not as positional argument, to ensure future extensibility.
-   Added documentation files into PyPI package.
-   Renamed --yes to --batch in the CLI.


### acefile 0.4.3 2017-06-27

-   Search the first 1024 sectors of files for the main archive header by
    default, in line with the reference implementations.
-   Some performance improvement for all decompression modes.


### acefile 0.4.2 2017-06-25

-   Decode all currently known NT file attributes.
-   Avoid rare IndexError when decompressing malformed archives.
-   Handle archives with multiple different passwords gracefully in CLI.
-   Print comments in ASCII box with a title to improve clarity in CLI.


### acefile 0.4.1 2017-06-24

-   Allow passwords to be specified as str or bytes, not only str.


### acefile 0.4.0 2017-06-21

-   Add support for encrypted archives using 160-bit blowfish.
-   Fix division by zero when using the CLI to list an archive containing
    directory members.


### acefile 0.3.0 2017-06-18

-   Implement decompression of archive and file comments.
-   Fix exception in decompression of ACE 1.0 archives using compression
    method 1 (LZ77).


### acefile 0.2.1 2017-06-17

First public release.


