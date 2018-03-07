type t

val pp : Format.formatter -> t -> unit

val parse_packet : Cs.t -> (t, [> `Msg of string ]) result

val serialize : t -> (Cs.t, [> `Msg of string ]) result

val hash : t -> (Cs.t -> unit) -> Types.openpgp_version ->
  (unit, [> `Msg of string]) result
