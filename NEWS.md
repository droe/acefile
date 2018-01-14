### acefile 0.6.9-dev



### acefile 0.6.8 2018-01-01

-   Fix build of c extension on platforms without C99 support enabled by
    default (pull req #12, @joesecurity).


### acefile 0.6.7 2017-08-21

-   Make restoration of mtime/atime on extraction optional, default off, and
    add -r --restore arguments to CLI.
-   Parse NT security information from FILE headers when present and optionally
    restore file attributes and NT security information on extraction as far as
    the platform supports it (issue #4).


### acefile 0.6.6 2017-08-05

-   Restore mtime and atime on extraction of files (issue #7).
-   Add -V --version arguments to CLI (issue #8).


### acefile 0.6.5 2017-08-01

-   Remove ACE 2.0 PIC mode width multiple of planes restriction (issue #6).
-   Improve exception messages and CLI exception handling.
-   Add SIGINFO handler to CLI on platforms that support it.
-   Add 270 additional ACE archives to corpus of test archives.


### acefile 0.6.4 2017-07-26

-   Fix signedness of ACE 2.0 SOUND mode diff calculations (issue #5).
-   Add basic debugging facility: `acefile.DEBUG = True` and CLI `--debug`
    hidden option.


### acefile 0.6.3 2017-07-23

-   10% performance increase for larger archives by avoiding excessive LZ77
    dictionary truncations.
-   Improve error handling of acebitstream.BitStream.
-   Improve unit test integration and coverage; `setup.py test` now supported.


### acefile 0.6.2 2017-07-19

-   Library API: Export open instead of AceArchive on import * from acefile.
-   Add high-performance BitStream implementation as optional c extension,
    resulting in over 50% speed increase for LZ77 archives.


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


