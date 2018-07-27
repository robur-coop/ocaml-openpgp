type t

open Rresult

val parse_packet : Cs.t -> (t, [> `Incomplete_packet | R.msg] )result
(** [parse_packet data] is the deserialized session packet contained in [data].
    The parsed packet can be re-serialized using [serialize].
    Note that the message itself (containing a symmetric key payload)
    is NOT decrypted (see [decrypt]).
*)

val pp : Format.formatter -> t -> unit
(** [pp formatter pkt] is the pretty-printer for [t] *)

val serialize : t -> (Cs.t, [> R.msg] ) result
(** [serialize session_packet] is the byte representation of [session_packet].
    The byte representation can be deserialized using [parse_packet].
*)

val hash : t -> (Cs.t -> unit) -> Types.openpgp_version ->
  (unit, [> R.msg]) result
(** [hash pkt hash_cb openpgp_version] calls [hash_cb] with the serialized [pkt]
*)

val matches_key : Public_key_packet.private_key -> t -> bool
(** [matches_key sk session_packet] is true if [session_packet]
    references the key id of [sk].*)

val decrypt : Public_key_packet.private_key -> t ->
  (Types.symmetric_algorithm * Cs.t, [> R.msg]) result
(** [decrypt private_key session_packet] is a tuple of
    (symmetric algorithm * symmetric key) resulting of the
    decryption of the [session_packet] using [private_key].
*)

val create : ?g:Nocrypto.Rng.g -> Public_key_packet.t ->
  Types.symmetric_algorithm ->
  (Cs.t * t, [> R.msg] ) result
(** [create ?rng target_pk key_byte_length] is a tuple of
    a key of [key_byte_length] bytes randomly generated using ?rng,
    and the same random key encrypted to the [target_pk].
*)
