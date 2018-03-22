(** https://tools.ietf.org/html/rfc4880#section-5.6 *)

open Rresult

val parse : ([> R.msg ] as 'error) Cs.R.rt -> (string, 'error) result
(** [parse cs_r] is the decompressed contents of [cs_r].*)
