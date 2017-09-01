type t = string

val parse_packet : Cs.t -> (t, 'error) Rresult.result

val hash : t -> (Cs.t -> unit) -> Types.openpgp_version -> unit

val pp : Format.formatter -> t -> unit
