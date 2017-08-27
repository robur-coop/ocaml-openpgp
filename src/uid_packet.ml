open Rresult

  type t = string

  let parse_packet (buf : Cs.t) : (t, 'error) result =
    (* 5.11.  User ID Packet (Tag 13)
   A User ID packet consists of UTF-8 text that is intended to represent
   the name and email address of the key holder.  By convention, it
   includes an RFC 2822 [RFC2822] mail name-addr, but there are no
   restrictions on its content.  The packet length in the header
       specifies the length of the User ID.*)
    (* TODO UTF-8 validation *)
    let s = Cs.to_string buf in
    let()=Logs.debug (fun m -> m "UID: '%S'" s) in
    R.ok s

let hash (t:string) hash_cb version =
  let cs = Cs.of_string t in
  begin match version with
  | Types.V3 -> () (* TODO not implemented *)
  | Types.V4 ->
    hash_cb (Cs.of_string "\xB4") ;
    let len = Cstruct.create 4 in
    Cstruct.BE.set_uint32 len 0 (String.length t
                                 |>Int32.of_int) ;
    hash_cb len ;
  end ;
  hash_cb cs
