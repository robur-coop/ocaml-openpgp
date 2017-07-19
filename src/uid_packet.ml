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
    R.ok (Cs.to_string buf)
