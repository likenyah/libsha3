# SHA-3

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/E1E65IUF4)

An implementation of the SHA-3 family of functions - SHA3-224, SHA3-256,
SHA3-384, SHA3-512 - as defined in [FIPS 202][url-fips202]. Though this aims to
be a correct and clearly-documented implementation suitable for embedding
directly into other programs, the main purpose of is really just to practice
implementing a specification. As such, **do not** use this for anything
important unless you can verify that there are no issues. (Though please tell
me if there are, since that's kind of the whole point of this exercise.)

## Performance Anecdotes

Built and executed on an Intel i5 9600K (Skylake) CPU, SHA3-256 is:

* About 23% slower than distribution OpenSSL on 1 GiB of input when built with
  `-mtune=generic`. (464 MiB/s vs 358 MiB/s)
* About 1.9% slower than distribution OpenSSL on 1 GiB of input when built with
  `-march=skylake`. (464 MiB/s vs 455 MiB/s)

This is only a rough comparison. These tests were performed by measuring the
execution time of `sha3_update()`, `sha3_final()`, `EVP_DigestUpdate()`, and
`EVP_DigestFinal()`. Input was read from a zero-filled 8 KiB
statically-allocated buffer. Measurements are the average of 10 runs.

[url-fips202]: https://dx.doi.org/10.6028/NIST.FIPS.202
