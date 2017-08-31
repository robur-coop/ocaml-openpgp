ocaml-openpgp
===========

OpenPGP library (RFC 4880)
--------------------------

This library implements rudimentary support for OpenPGP.

Right now it's a work in progress and should not be used for anything critical to security in a real-world situation.

- The first milestone will be implementing support for signature verification / generation, and support for RSA and DSA keys.

- Encryption is out of scope for now.

- Supporting El-Gamal and elliptic curve keys are out of scope due to lack of support for these in [nocrypto](https://github.com/mirleft/nocrypto).

I could be persuaded to add these if someone can point me to maintained libraries implementing these.

- Note that key expiry, or anything else related to dates, is not supported for the time being either.

### Building

```bash
opam pin nocrypto 'https://github.com/cfcs/nocrypto#fix_pkcs1'
opam install topkg-care rresult nocrypto cstruct hex usane logs cmdliner bos fpath oUnit qcheck
topkg bu
```

### Cmdline usage

The library ships with a sample application in `app/opgp.ml`.

Usage is available with `--help`.

- Verifying a detached signature:
```bash
./_build/app/opgp.native verify -vv --pk MY_KEY.asc --signature MY_SIGNATURE.asc --target MYSIGNEDFILE
```

### Resources

The spec is included in this repository in the rfc/ subdirectory.

[RFC 4880 - OpenPGP Message Format](rfc/RFC+4880+-+OpenPGP+Message+Format.html)
