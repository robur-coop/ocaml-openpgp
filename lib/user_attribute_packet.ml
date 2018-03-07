open Rresult

type t = Cs.t

let pp ppf t =
  Fmt.pf ppf "{ @[<v>unimplemented user attribute:@ %a@]}" Cs.pp_hex t

let parse_packet (buf : Cs.t) : (t, 'error) result =
  (* RFC 4880: 5.12: The User Attribute packet is made up of one or more
     attribute subpackets.  Each subpacket consists of a subpacket header and a
     body.  The header consists of:
     - the subpacket length (1, 2, or 5 octets)
     - the subpacket type (1 octet)
     and is followed by the subpacket specific data.*)

  (* RFC 4880: 5.12: The only currently defined subpacket type is 1, signifying
     an image.
     An implementation SHOULD ignore any subpacket of a type that it does
     not recognize.  Subpacket types 100 through 110 are reserved for
     private or experimental use.*)

  (* we go for that approach, ignoring them entirely: *)
  Ok buf

let hash t (hash_cb:Cs.t->unit) version : (unit, 'error) result =
  begin match version with
    | Types.V3 ->
      Types.error_msg (fun m ->
          m "user attribute hashing for OpenPGP V3 not implemented")
    | Types.V4 ->
      hash_cb (Cs.of_string "\xD1") ; (*0xD1: see 5.2.4. Computing Signatures*)
      Ok (hash_cb @@ Cs.BE.create_uint32 (Cs.len t |> Int32.of_int))
  end >>| fun () ->
  hash_cb t

let serialize (t:t) = Ok (t:Cs.t)
