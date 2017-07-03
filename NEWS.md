
### acefile 0.5.3-dev

-   Add AceArchive.is_locked().
-   Replace AceMember.params with decoded AceMember.dicbits.
-   Show more metadata in CLI --verbose archive info and --list.


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


