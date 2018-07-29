OpenPGP library (RFC 4880) [![Build Status](https://travis-ci.org/cfcs/ocaml-openpgp.svg?branch=master)](https://travis-ci.org/cfcs/ocaml-openpgp)
===========================================

This library implements rudimentary support for OpenPGP as used with signatures,
and has basic support for decryption of messages.

__Right now it's a work in progress and should not be used for anything critical to security in a real-world situation.__

- Encryption is being worked on.

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
opam pin add -n gmap 'https://github.com/hannesm/gmap.git'
opam pin add -n nocrypto -k git 'https://github.com/mirleft/ocaml-nocrypto.git#79d5db2488e338d161d7e170cd681a8120ce07d1'
opam install alcotest bos cmdliner cs cstruct fmt fpath gmap hex logs \
             nocrypto ptime qcheck rresult usane topkg
ocaml pkg/pkg.ml build
```

### Roadmap

- Consider support for inline signatures
- ~~GPG-agent protocol~~ the GPG-agent protocol is inherently unsafe for
  signing operations. Other projects (`git`, `qubes`, `enigmail`) seem to
  implement GnuPG integration by shelling out to the `gpg` cli.
  Some limited compatibility with that seems more useful to implement.
- [Git signing / verification](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work), see [section below](#git-openpgp-integration)
- MirageOS version of [Qubes split-gpg](https://github.com/QubesOS/qubes-app-linux-split-gpg)

### Cmdline usage

The library ships with a sample application in `app/opgp.ml`.

**Usage details is available with `opgp --help`.**
Examples of how to use the application are also given there.

It can currently:
- `opgp genkey`: Generate a (DSA | RSA) private key
- `opgp sign`: Produce a detached signature on a file
- `opgp convert`: Derive a public key from a private key
- `opgp verify`: Verify a detached signature
- `opgp list-packets`: List packets contained in armored or binary PGP streams
- `opgp decrypt`: Decrypt messages to RSA root keys
  - Decompress ZIP(RFC1951) and ZLIB messages - BZip2 is still missing


### Git / OpenPGP integration

`git` integrates cryptographic signature creation and verification by
calling out to `gpg`.
Peter Todd has a nice article about that in the
[documentation for his OpenTimeStamps project](https://github.com/opentimestamps/opentimestamps-client/blob/master/doc/git-integration.md)
(which is a separate project that combines `gpg`-signatures with
date proofs using append-only logs like BitCoin).

A _minimally **GnuPG**-compatible_ program `opgp-git` is provided with
the `ocaml-openpgp` distribution to replace the use of `gpg` in this scenario.
- **NB: At the moment only verification is supported,** and only against a
  single public key contained in `~/opgp-git.asc` - as thus this is not super
  useful, but is there as an example, and to remind me to fix the API to
  support some sort of PKI / key database.

To activate it, you will have to change the `gpg.program` variable to
point to `opgp-git` instead of `gpg`:

```shell
$ git config --global gpg.program "$(opam config var openpgp:bin)/opgp-git"
```

- **NOTE** that `opgp-git` **does not** implement the full GnuPG command-line
interface, it merely implements the handling of the functionality
expected by `git`, namely `["opgp-git", "--verify", "$file", "-"]` and
`["opgp-git", "-bsau", "$key"]`.
See the `gpg.program` entry in `man git-config` for more details.

Once configured, you can "manually" sign commits at commit-time with
`git commit --gpg-sign=KEYID`, or you can configure git to do this automatically
(see the `commit.gpgSign` entry in `man git-config` for more details).

- To retrieve the purported PGP key for a Github account, you can add `.gpg` to
the end of their URL. Example: https://github.com/rootkovska.gpg


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
- [PGPy (Python)](https://github.com/SecurityInnovation/PGPy/)
- [Bigloo (Scheme?)](https://www-sop.inria.fr/indes/fp/Bigloo/doc/bigloo-16.html#OpenPGP)
- [NeoPG (C++/Botan)](https://neopg.io)
- [Sequoia-PGP (Rust/libnettle)](https://sequoia-pgp.org/)
- [pbp "pretty bad protocol" (Rust/libdalek)](https://github.com/withoutboats/pbp)
  - see also the author's [git commit signing tool](https://github.com/withoutboats/bpb)
