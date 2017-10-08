ocaml-openpgp
===========

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
