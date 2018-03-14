(* https://tools.ietf.org/html/rfc4880#section-13.9 *)

(* This is an implementation of OpenPGP's CFB mode.
   Note that OpenPGP has their own homegrown version; this is not
   textbook CFB.

   [finalize_decryption] takes care of checking the "MDC"
   ( SHA1 hash of:
   - "IV" (the [block_size] bytes that prefixes the plaintext)
   - the "quick check" (which we just randomly generate)
   - the plaintext
   - the [mdc_header] (two bytes, see below).
   )
*)

open Rresult

type encryption = [`encryption]
type decryption = [`decryption]

type mode = [ encryption | decryption ]

type _ t

val decrypt : key:Cs.t -> Cs.t ->
  (Cs.t, [> R.msg]) result
(** [decrypt ~key ciphertext] is the
    decrypted plaintext corresponding to [ciphertext].
    Error if the SHA1 integrity check fails.
*)

val encrypt : ?g:Nocrypto.Rng.g -> key:Cs.t -> Cs.t ->
  (Cs.t, [> R.msg]) result
(** [encrypt ~key plaintext] is [plaintext] encrypted with [key].*)


val init_encryption : ?g:Nocrypto.Rng.g -> key:Cs.t ->
  (encryption t * Cs.t, [> R.msg]) result
(** [init_encryption ~key] is a tuple of
    (state, initial_output) loaded with [key] that may
    be used for streaming encryption.
*)

val init_decryption : key:Cs.t -> (decryption t, [> R.msg]) result
(** [init_decryption ~key ciphertext] is (state, initial_output)
    loaded with [key] that may be used for streaming decryption.
*)

val finalize_encryption : encryption t -> Cs.t option ->
  (Cs.t list, [> R.msg]) result
(** [finalize_encryption state plaintext] is the final ciphertext
    encrypted with the key loaded into [state]
    (including the encrypted SHA1 MDC of the complete plaintext encrypted by
    this state).
*)

val finalize_decryption : decryption t -> Cs.t option ->
  (Cs.t, [> R.msg]) result
(** [finalize_decryption state ciphertext] is the final plaintext
    decrypted with the key loaded into [state].
    Error if the SHA1 MDC integrity check fails.
*)
