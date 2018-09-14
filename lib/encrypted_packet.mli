type encrypted
type decrypted

type _ t

val pp : Format.formatter -> _ t -> unit
(** [pp fmt t] is [t] pretty-printed on [fmt].*)

val hash : encrypted t -> (Cs.t -> unit) -> Types.openpgp_version ->
  (unit, [> Rresult.R.msg]) result

val serialize : encrypted t -> (Cs.t, [> Rresult.R.msg]) result

val parse_packet : Cs.t -> (encrypted t, [> Rresult.R.msg]) result

val decrypt : ?key:Cs.t -> encrypted t -> (Cs.t, [> Rresult.R.msg]) result

val encrypt : ?g:Nocrypto.Rng.g -> symmetric_key:Cs.t -> Cs.t ->
  (encrypted t, [> Rresult.R.msg]) result
(** TODO how do we specify the symmetric encryption algorithm?? *)
