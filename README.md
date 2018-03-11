ocaml-openpgp
===========

[[![Build Status](https://api.travis-ci.org/cfcs/ocaml-openpgp.svg?branch=master)]](https://travis-ci.org/cfcs/ocaml-openpgp)

OpenPGP library (RFC 4880)
--------------------------

This library implements rudimentary support for OpenPGP as used with signatures.

Right now it's a work in progress and should not be used for anything critical to security in a real-world situation.

- Encryption is out of scope for now.

- Supporting El-Gamal and elliptic curve keys are out of scope due to lack of support for these in [nocrypto](https://github.com/mirleft/nocrypto).

I could be persuaded to add these if someone can point me to maintained libraries implementing these.

### Contributing

Contributions are greatly appreciated!

To prevent duplication/collision of work, please consider leaving a note in the [issues section](https://github.com/cfcs/ocaml-openpgp/issues/) before implementing large changes.

The library and API is still a volatile as it is still being developed.

Suggestions for things to improve:
- Writing more tests, for example for primitives in `types.ml`.
  - Tests for vulnerabilities that have affected other OpenPGP implementations.
  - Tests pertaining to diverse/"exotic" keys
- Adding useful debug output, or extending existing pretty-printers with more information.
- Suggestions / signatures for a better API, or scenarios that the library should support.
- CLI commands or arguments (this is one of my first times using `cmdliner` - I'm sure things can be improved)
- Performance improvements

### Building

The library currently depends on the unreleased `Usane` library for unsigned
 arithmetic, and on my unreleased wrappers around `Cstruct`, called `cs`.

```bash
opam pin add -n usane 'https://github.com/hannesm/usane.git'
opam pin add -n cs 'https://github.com/cfcs/ocaml-cs.git'
opam install alcotest bos cmdliner cs cstruct fmt fpath hex logs \
             nocrypto ptime qcheck rresult usane topkg
ocaml pkg/pkg.ml build
```

### Roadmap

- Consider support for inline signatures
- GPG-agent protocol
- MirageOS version of [Qubes split-gpg](https://github.com/QubesOS/qubes-app-linux-split-gpg)

### Cmdline usage

The library ships with a sample application in `app/opgp.ml`.

Usage is available with `--help`.
Examples of how to use the application are also given there.

It can currently:
- Generate a (DSA | RSA) private key (`opgp genkey`)
- Produce a detached signature on a file (`opgp sign`)
- Derive a public key from a private key (`opgp convert`)
- Verify a detached signature (`opgp verify`)
- List packets contained in armored or binary PGP streams (`opgp list-packets`)

### Resources

The spec is included in this repository in the rfc/ subdirectory.

[RFC 4880 - OpenPGP Message Format](rfc/RFC+4880+-+OpenPGP+Message+Format.html)

### Alternative implementations
- [GnuPG (C, using libgcrypt)](https://gnupg.org/)
  - [GnuPG's list of FOSS implementations](https://wiki.gnupg.org/OtherFreeSoftwareOpenPGP)
- [Keybase PGP (C)](https://github.com/keybase/kbpgp/)
- [libsimplepgp (C)](http://mrmekon.tumblr.com/post/12781181931/announcing-libsimplepgp)
- [NetPGP (C)](http://netpgp.com/)
  - [maintained/improved fork](https://github.com/riboseinc/rnp)
- [pgcrypto (C, from postgresql)](https://doxygen.postgresql.org/pgp-info_8c.html)
- [TinyGPG (C, using libgcrypt)](https://github.com/gpg/tgpg)
- [CalcCrypto OpenPGP (C++)](https://github.com/calccrypto/OpenPGP)
- [Golang OpenPGP (Go)](https://godoc.org/golang.org/x/crypto/openpgp)
- [hOpenPGP (Haskell)](https://hackage.haskell.org/package/hOpenPGP-2.5.5)
  - [may be this, TODO](https://github.com/singpolyma/OpenPGP-Haskell/)
- [Bouncy Castle (Java)](https://bouncycastle.org/)
- [Open-Keychain](https://github.com/open-keychain/open-keychain/)
- [Google End-to-End (JavaScript)](https://github.com/google/end-to-end/blob/master/src/javascript/crypto/e2e/openpgp)
- [OpenPGP.js (JavaScript)](https://github.com/openpgpjs/openpgpjs/)
- [Mailvelope OpenPGP.js (JavaScript)](https://www.mailvelope.com/en)
- [ObjectivePGP (Objective-C? TODO)](https://github.com/krzyzanowskim/ObjectivePGP/)
- [Crypt::OpenPGP (perl)](https://github.com/btrott/Crypt-OpenPGP/tree/master/t)
  - [CPAN package](https://metacpan.org/pod/Crypt::OpenPGP)
- [PGPy](https://github.com/SecurityInnovation/PGPy/)
- [Bigloo (Scheme?)](https://www-sop.inria.fr/indes/fp/Bigloo/doc/bigloo-16.html#OpenPGP)
