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
 arithmetic, and on an unmerged patch for `nocrypto` that implements PKCS1
 support.

```bash
opam pin add -n nocrypto 'https://github.com/cfcs/nocrypto.git#fix_pkcs1'
opam pin add -n usane 'https://github.com/hannesm/usane.git'
opam install alcotest bos cmdliner cstruct fmt fpath hex logs \
             nocrypto ptime qcheck rresult usane topkg
ocaml pkg/pkg.ml build
```

### Roadmap

- Implementing support for secret/private keys
- Generating keys that are accepted by GnuPG 2
- Generating detached signatures
- MirageOS version of [Qubes split-gpg](https://github.com/QubesOS/qubes-app-linux-split-gpg)

### Cmdline usage

The library ships with a sample application in `app/opgp.ml`.

Usage is available with `--help`.

- Generating public keys (currently `--uid` is only option flag):
```bash
$ ./opgp.native genkey --uid 'My voice is my passport' | gpg2 --import
gpg: key 9C829342D5E17B69: public key "My voice is my passport" imported
gpg: Total number processed: 1
gpg:               imported: 1
$ gpg2 --list-keys passport
pub   dsa2048 2017-09-15 [SC] [expires: 2018-09-15]
      6390AE6B56040888C289A2F79C829342D5E17B69
uid           [ unknown] My voice is my passport
```

- Verifying a detached signature:
```bash
./_build/app/opgp.native verify -vv --pk MY_KEY.asc \
    --signature MY_SIGNATURE.asc  --target MYSIGNEDFILE
```

- Listing packets:
```
$ ./_build/app/opgp.native list-packets --target dsadetached_pub.asc
armor type: ASCII public key block
99 01 0d 04 59 a1 f7 c1 01 08 00 d9 f6 05 3d 5e
92 06 e4 5f df a3 11 0a 1f 0b 90 bd 6d 64 c5 71
16 a0 bd 0f 98 d1 d8 16 f9 39 98 9e 19 f2 ab 9d
3d d1 b7 ef 61 8a 80 6b 1e b1 7a b6 3a b4 59 0e
e7 d4 e3 a1 bf d4 e2 ab 93 2c c7 3f a0 3f 2e 62
6d a0 b4 9a ba b1 f8 22 34 bc a3 ab 84 41 8d e9
e0 87 a2 8a dd 20 66 62 43 19 5d 19 c3 62 9a 4f
47 cb 6e 42 a3 b2 a8 58 49 38 a3 74 12 c5 b8 84
4a a5 66 fe 43 16 2b 17 26 9b 4d 6b 99 41 0b e8
b8 8e 3a f0 8d 4d 51 7a cc f4 87 9d 1b 44 23 39
b8 c8 b3 7e b8 41 3a 9f 97 0a 4a 77 04 ef 47 6d
9a 70 bc 8a fb a2 13 35 68 43 15 ff 96 d9 0b 29
4d 59 ec 31 81 a4 bb 26 c2 36 f8 f6 8a 7f 10 10
6b d2 fa fa eb 99 8f d6 4b 43 c4 78 ec 59 8b 6c
2e b3 a3 e2 09 3a d7 38 4e 77 0a f5 c1 22 76 18
cf 8a d0 17 f3 a6 7f b1 45 9c 28 8e 25 16 c5 bd
b8 25 b8 46 0f 3f 05 49 23 c1 57 00 11 01 00 01
b4 09 64 73 61 64 65 74 61 63 68 89 01 54 04 13
01 08 00 3e 16 21 04 c6 8d ac 2d c1 6d d3 48 e3
28 a0 5a 24 87 fb 89 2f bd 79 76 05 02 59 a1 f7
c1 02 1b 03 05 09 03 c2 67 00 05 0b 09 08 07 02
06 15 08 09 0a 0b 02 04 16 02 03 01 02 1e 01 02
17 80 00 0a 09 10 24 87 fb 89 2f bd 79 76 db a9
07 fe 33 50 67 93 8d ba d2 68 1b 46 65 27 50 b4
b5 1d 79 b5 76 d5 c0 15 95 5f e5 e7 a1 91 0d b4
31 3e ee 5b 93 4b d7 70 ed 91 c5 71 49 a6 7a b5
c8 f9 e1 79 47 86 a8 2c 01 9f aa 23 b8 03 0c 7b
07 bd ec 03 6b 05 51 06 8b 7b 0f 99 6b 84 18 76
d0 76 9a 19 82 fa 2b da f3 e5 f5 b9 07 18 0f 45
3f ff a8 eb d7 a3 d7 5f 5c dc b0 c3 6f 70 96 8b
ae d2 b7 13 a5 96 4d 22 a6 6d 3d 90 84 36 16 66
38 a1 99 e5 69 bd 48 a8 17 f1 58 d7 80 50 a9 4d
08 34 34 dd 70 0f 80 44 e3 d3 d6 95 56 99 91 e0
f8 f7 f3 88 4c 76 e3 11 c5 bd fc 70 14 b6 90 13
1a 29 1a cf 1a a3 16 24 c8 be 10 d0 fb f6 ba 75
9a cc ca 8e 03 f1 9c 59 5f 50 41 3f f7 2a 05 52
09 fb d6 7f 84 aa 8d dd a7 47 fb 20 d1 7b b1 cd
14 f7 cb 6a 5e 0e ec 8d 0b 00 72 2c 67 17 91 db
77 d8 e1 7b 51 61 ac f6 3e bd c2 2a df 3b 53 16
82 12 b9 01 0d 04 59 a1 f7 c1 01 08 00 b4 63 60
fa 83 55 72 7f 91 f1 87 c7 64 f0 b5 48 e4 f3 81
98 e2 d4 b6 bb 39 fe e1 c4 a9 7b 9a a5 8a 39 64
61 83 5d 9d be dd 3b 17 cc 50 ec c4 27 7a ba 64
92 aa 6e 6a 80 d4 75 04 4f ac 74 f9 1e 55 d3 28
26 d8 aa ba 57 31 67 2d 41 d2 30 44 62 73 80 d8
a5 78 50 44 8e b9 7c e3 79 d2 d4 a6 42 53 8b 79
f8 c1 e7 67 a6 c0 33 cb f2 a6 68 b0 27 42 6e aa
d3 34 b3 27 03 d8 a5 76 28 63 b2 d4 3d 04 b7 55
16 ab 13 9c 86 c6 d9 9a db ce e3 af 24 14 9e 92
5f b8 db 33 4b 27 6c ff cc 2a a4 52 0a 25 c4 69
42 e6 bf 66 d7 5c fd 88 51 e7 8a 28 35 23 d0 d0
a8 94 74 60 66 62 33 d7 61 04 19 ab 23 6b 81 97
17 0f 37 c5 e0 02 e4 14 d5 09 fe a9 19 10 a3 c9
10 c3 1e 84 aa 0c f1 f6 47 9d 51 83 f8 c1 a0 ce
4d 06 6d 05 43 28 df a1 62 97 26 c8 b8 df b4 89
88 af c1 cc 58 2c d7 26 fa 12 33 7e cd 00 11 01
00 01 89 01 3c 04 18 01 08 00 26 16 21 04 c6 8d
ac 2d c1 6d d3 48 e3 28 a0 5a 24 87 fb 89 2f bd
79 76 05 02 59 a1 f7 c1 02 1b 0c 05 09 03 c2 67
00 00 0a 09 10 24 87 fb 89 2f bd 79 76 66 a7 07
fe 21 81 29 07 f5 bf 5c 7e 91 86 36 c0 5b 96 e7
46 ba c6 cf b1 5a 16 17 4d 77 89 7d e6 6a b6 89
09 a7 5c 0b 39 6d 51 64 0a 58 35 3e 3e 3b 90 dd
20 22 57 b6 3e 99 62 41 3b 57 ec 1d 20 c1 a6 fd
2c fd 8a e6 0d 43 15 c4 64 12 c6 53 f5 13 83 26
1d 96 37 f0 d7 45 e4 a0 4f 34 0f 56 73 a7 e8 d2
21 8d 6a 34 0c 9d 62 7d d6 f0 59 96 78 97 e3 b6
1f 81 6e 10 6f 6e 9e 06 f5 37 ff 87 4b d9 84 90
2d 5e 7c bd c1 25 3c f1 d2 38 ab 20 9f db 7d 82
94 31 ff 53 24 96 26 84 2c 88 3b 9f 13 37 a1 ca
b5 62 69 46 cf 64 e7 f4 2b 43 83 4c 3a 00 df e0
fb 11 ed 15 e1 f4 97 e2 cd 23 8e 0f 31 b0 45 4e
38 32 a1 35 4c a1 4c d5 db 2f 79 1e 2b 72 8d 33
2a 5f e9 f3 6c e2 9a a2 5a 16 dd b7 c2 98 df 02
be 93 d5 18 b7 68 8c c4 d6 d1 06 56 6a 5e 96 5d
c9 44 0b db 92 7b aa 51 e3 2e b2 e8 be 8e e1 ae
74
Packets:
|  Public key: [public key packet: created: 2017-08-26 22:35:45 +00:00
               ; 2048-bit (e: 65537) RSA encryption & signing key
               ; SHA1 fingerprint: c68dac2dc16dd348e328a05a2487fb892fbd7976
               ]
   Hexdump: 04 59 a1 f7 c1 01 08 00 d9 f6 05 3d 5e 92 06 e4
   5f df a3 11 0a 1f 0b 90 bd 6d 64 c5 71 16 a0 bd
   0f 98 d1 d8 16 f9 39 98 9e 19 f2 ab 9d 3d d1 b7
   ef 61 8a 80 6b 1e b1 7a b6 3a b4 59 0e e7 d4 e3
   a1 bf d4 e2 ab 93 2c c7 3f a0 3f 2e 62 6d a0 b4
   9a ba b1 f8 22 34 bc a3 ab 84 41 8d e9 e0 87 a2
   8a dd 20 66 62 43 19 5d 19 c3 62 9a 4f 47 cb 6e
   42 a3 b2 a8 58 49 38 a3 74 12 c5 b8 84 4a a5 66
   fe 43 16 2b 17 26 9b 4d 6b 99 41 0b e8 b8 8e 3a
   f0 8d 4d 51 7a cc f4 87 9d 1b 44 23 39 b8 c8 b3
   7e b8 41 3a 9f 97 0a 4a 77 04 ef 47 6d 9a 70 bc
   8a fb a2 13 35 68 43 15 ff 96 d9 0b 29 4d 59 ec
   31 81 a4 bb 26 c2 36 f8 f6 8a 7f 10 10 6b d2 fa
   fa eb 99 8f d6 4b 43 c4 78 ec 59 8b 6c 2e b3 a3
   e2 09 3a d7 38 4e 77 0a f5 c1 22 76 18 cf 8a d0
   17 f3 a6 7f b1 45 9c 28 8e 25 16 c5 bd b8 25 b8
   46 0f 3f 05 49 23 c1 57 00 11 01 00 01
|  UID: "dsadetach"
   Hexdump: 64 73 61 64 65 74 61 63 68
|  Signature: { signature type: [positive certification of uid and public key]
              ; public key algorithm: [RSA encrypt or sign]
              ; hash algorithm: [SHA256]
              ; subpackets:
              [
                 [Issuer_fingerprint SHA1: c68dac2dc16dd348e328a05a2487fb892fbd7976]
                 [Signature_creation_time UTC: 2017-08-26 22:35:45 +00:00]
                 Key usage flags:
                   {certify: true ;
                   sign data: true ;
                   encrypt communications: false ;
                   encrypt storage: false ;
                   authentication: false ;
                   raw decimal char: '\003'}
                 [Key expiration time: 1y365d]
                 Preferred_symmetric_algorithms
                 Pref. hash algorithms: [SHA256; SHA384; SHA512; SHA224; SHA1]
                 Preferred_compression_algorithms
                 Features
                 Key_server_preferences]
   Hexdump: 04 13 01 08 00 3e 16 21 04 c6 8d ac 2d c1 6d d3
   48 e3 28 a0 5a 24 87 fb 89 2f bd 79 76 05 02 59
   a1 f7 c1 02 1b 03 05 09 03 c2 67 00 05 0b 09 08
   07 02 06 15 08 09 0a 0b 02 04 16 02 03 01 02 1e
   01 02 17 80 00 0a 09 10 24 87 fb 89 2f bd 79 76
   db a9 07 fe 33 50 67 93 8d ba d2 68 1b 46 65 27
   50 b4 b5 1d 79 b5 76 d5 c0 15 95 5f e5 e7 a1 91
   0d b4 31 3e ee 5b 93 4b d7 70 ed 91 c5 71 49 a6
   7a b5 c8 f9 e1 79 47 86 a8 2c 01 9f aa 23 b8 03
   0c 7b 07 bd ec 03 6b 05 51 06 8b 7b 0f 99 6b 84
   18 76 d0 76 9a 19 82 fa 2b da f3 e5 f5 b9 07 18
   0f 45 3f ff a8 eb d7 a3 d7 5f 5c dc b0 c3 6f 70
   96 8b ae d2 b7 13 a5 96 4d 22 a6 6d 3d 90 84 36
   16 66 38 a1 99 e5 69 bd 48 a8 17 f1 58 d7 80 50
   a9 4d 08 34 34 dd 70 0f 80 44 e3 d3 d6 95 56 99
   91 e0 f8 f7 f3 88 4c 76 e3 11 c5 bd fc 70 14 b6
   90 13 1a 29 1a cf 1a a3 16 24 c8 be 10 d0 fb f6
   ba 75 9a cc ca 8e 03 f1 9c 59 5f 50 41 3f f7 2a
   05 52 09 fb d6 7f 84 aa 8d dd a7 47 fb 20 d1 7b
   b1 cd 14 f7 cb 6a 5e 0e ec 8d 0b 00 72 2c 67 17
   91 db 77 d8 e1 7b 51 61 ac f6 3e bd c2 2a df 3b
   53 16 82 12
|  Public subkey: [public key packet: created: 2017-08-26 22:35:45 +00:00
                  ; 2048-bit (e: 65537) RSA encryption & signing key
                  ; SHA1 fingerprint: be9e17324a392ca79e4a217894d58831115cb04e
                  ]
   Hexdump: 04 59 a1 f7 c1 01 08 00 b4 63 60 fa 83 55 72 7f
   91 f1 87 c7 64 f0 b5 48 e4 f3 81 98 e2 d4 b6 bb
   39 fe e1 c4 a9 7b 9a a5 8a 39 64 61 83 5d 9d be
   dd 3b 17 cc 50 ec c4 27 7a ba 64 92 aa 6e 6a 80
   d4 75 04 4f ac 74 f9 1e 55 d3 28 26 d8 aa ba 57
   31 67 2d 41 d2 30 44 62 73 80 d8 a5 78 50 44 8e
   b9 7c e3 79 d2 d4 a6 42 53 8b 79 f8 c1 e7 67 a6
   c0 33 cb f2 a6 68 b0 27 42 6e aa d3 34 b3 27 03
   d8 a5 76 28 63 b2 d4 3d 04 b7 55 16 ab 13 9c 86
   c6 d9 9a db ce e3 af 24 14 9e 92 5f b8 db 33 4b
   27 6c ff cc 2a a4 52 0a 25 c4 69 42 e6 bf 66 d7
   5c fd 88 51 e7 8a 28 35 23 d0 d0 a8 94 74 60 66
   62 33 d7 61 04 19 ab 23 6b 81 97 17 0f 37 c5 e0
   02 e4 14 d5 09 fe a9 19 10 a3 c9 10 c3 1e 84 aa
   0c f1 f6 47 9d 51 83 f8 c1 a0 ce 4d 06 6d 05 43
   28 df a1 62 97 26 c8 b8 df b4 89 88 af c1 cc 58
   2c d7 26 fa 12 33 7e cd 00 11 01 00 01
|  Signature: { signature type: [subkey binding]
              ; public key algorithm: [RSA encrypt or sign]
              ; hash algorithm: [SHA256]
              ; subpackets:
              [
                 [Issuer_fingerprint SHA1: c68dac2dc16dd348e328a05a2487fb892fbd7976]
                 [Signature_creation_time UTC: 2017-08-26 22:35:45 +00:00]
                 Key usage flags:
                   {certify: false ;
                   sign data: false ;
                   encrypt communications: true ;
                   encrypt storage: true ;
                   authentication: false ;
                   raw decimal char: '\012'}
                 [Key expiration time: 1y365d]]
   Hexdump: 04 18 01 08 00 26 16 21 04 c6 8d ac 2d c1 6d d3
   48 e3 28 a0 5a 24 87 fb 89 2f bd 79 76 05 02 59
   a1 f7 c1 02 1b 0c 05 09 03 c2 67 00 00 0a 09 10
   24 87 fb 89 2f bd 79 76 66 a7 07 fe 21 81 29 07
   f5 bf 5c 7e 91 86 36 c0 5b 96 e7 46 ba c6 cf b1
   5a 16 17 4d 77 89 7d e6 6a b6 89 09 a7 5c 0b 39
   6d 51 64 0a 58 35 3e 3e 3b 90 dd 20 22 57 b6 3e
   99 62 41 3b 57 ec 1d 20 c1 a6 fd 2c fd 8a e6 0d
   43 15 c4 64 12 c6 53 f5 13 83 26 1d 96 37 f0 d7
   45 e4 a0 4f 34 0f 56 73 a7 e8 d2 21 8d 6a 34 0c
   9d 62 7d d6 f0 59 96 78 97 e3 b6 1f 81 6e 10 6f
   6e 9e 06 f5 37 ff 87 4b d9 84 90 2d 5e 7c bd c1
   25 3c f1 d2 38 ab 20 9f db 7d 82 94 31 ff 53 24
   96 26 84 2c 88 3b 9f 13 37 a1 ca b5 62 69 46 cf
   64 e7 f4 2b 43 83 4c 3a 00 df e0 fb 11 ed 15 e1
   f4 97 e2 cd 23 8e 0f 31 b0 45 4e 38 32 a1 35 4c
   a1 4c d5 db 2f 79 1e 2b 72 8d 33 2a 5f e9 f3 6c
   e2 9a a2 5a 16 dd b7 c2 98 df 02 be 93 d5 18 b7
   68 8c c4 d6 d1 06 56 6a 5e 96 5d c9 44 0b db 92
   7b aa 51 e3 2e b2 e8 be 8e e1 ae 74
```

### Resources

The spec is included in this repository in the rfc/ subdirectory.

[RFC 4880 - OpenPGP Message Format](rfc/RFC+4880+-+OpenPGP+Message+Format.html)
