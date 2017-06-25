
### acefile 0.4.2-dev

-   Decode all currently known NT file attributes.
-   Avoid rare IndexError when decompressing malformed archives.


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


