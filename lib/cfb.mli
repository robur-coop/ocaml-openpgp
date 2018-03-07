open Rresult

type encryption = [`encryption]
type decryption = [`decryption]

type mode = [ encryption | decryption ]

type _ t

val decrypt : key:Cs.t -> Cs.t ->
  (Nocrypto.Hash.digest * Cs.t, [> R.msg]) result
(** [decrypt ~key ciphertext] is the
    decrypted plaintext corresponding to [ciphertext].
    No integrity checking is performed.
*)

val encrypt : ?g:Nocrypto.Rng.g -> key:Cs.t -> Cs.t ->
  (Nocrypto.Hash.digest * Cs.t, [> R.msg]) result
(** [encrypt ~key plaintext] is [plaintext] decrypted with [key].*)


val init_encryption : ?g:Nocrypto.Rng.g -> key:Cs.t ->
  (encryption t * Cs.t, [> R.msg]) result
(** [init_encryption ~key] is a tuple of
    (state, initial_output) loaded with [key] that may
    be used for streaming encryption.
*)

val init_decryption : key:Cs.t -> Cs.t ->
  (decryption t * Cs.t, [> R.msg]) result
(** [init_decryption ~key ciphertext] is (state, initial_output)
    loaded with [key] that may be used for streaming decryption.
    NOTE / TODO: [ciphertext] must be at least (block_size+2) bytes
*)

val finalize_encryption : encryption t -> Cs.t ->
  (Nocrypto.Hash.digest * Cs.t, [> R.msg]) result
(** [finalize_encryption state plaintext] is (digest,plaintext)
    where [digest] is the SHA1 digest of the complete plaintext encrypted by
    this state.
    TODO / NOTE: doesn't include the first block atm
*)

val finalize_decryption : decryption t -> Cs.t ->
  (Nocrypto.Hash.digest * Cs.t, [> R.msg]) result
(** [finalize_decryption state ciphertext] is (digest,plaintext)
    where [digest] is the SHA1 digest of the complete plaintext decrypted by
    this state
    TODO / NOTE: doesn't include the first block atm
*)

(* TODO expose the streaming functions *)
