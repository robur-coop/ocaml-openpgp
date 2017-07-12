open Rresult
open Types
open Pervasives (* TODO only for debugging *)

(* TODO
   BEGIN PGP
       MESSAGE
       PRIVATE KEY BLOCK
       MESSAGE, PART X/Y
       MESSAGE, PART X
       SIGNATURE
*)
let begin_public_key_block = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----"
let end_public_key_block = Cstruct.of_string "-----END PGP PUBLIC KEY BLOCK-----"

let decode_ascii_armor (buf : Cstruct.t) =
  (* see https://tools.ietf.org/html/rfc4880#section-6.2 *)
  let max_line_length = 73 in
  Cs.index buf ~max_offset:max_line_length '\n'
  |> R.of_option ~none:(fun () -> Error `Invalid)
  >>= fun type_len ->
  begin match Cs.sub buf 0 type_len with
  | b when Cstruct.equal b begin_public_key_block -> Ok Ascii_public_key_block
  | _ -> Error `Invalid_key_type
  end
  >>= fun pkt_type ->

  (* skip additional headers (like "Version:") *)
  Cs.find ~offset:type_len buf Cs.(of_string "\n\n")
  |> R.of_option ~none:(fun()-> Error `Missing_body)
  >>= fun header_end ->
  let header_end = header_end + String.(length "\n\n") in (* TODO add a Cs.find that includes length of matched needle *)

  begin match pkt_type with
  | Ascii_public_key_block ->
    Cs.find ~offset:header_end buf end_public_key_block
    |> R.of_option ~none:(fun()-> Error `Missing_end_block)
  | Ascii_private_key_block
  | Ascii_message
  | Ascii_message_part_x _
  | Ascii_message_part_x_of_y _
  | Ascii_signature ->
     Error `Malformed (* TODO `Not_implemented *)
  end
  >>= fun packet_end ->

  Cs.find buf ~offset:header_end ~max_offset:packet_end Cs.(of_string "\n=")
  |> R.of_option ~none:(fun()-> Error `Missing_crc24)
  >>= fun body_end ->
  let body_end = body_end + String.(length "\n") in

  (* 4: length of base64-encoded crc24 *)
  Cs.sub buf (body_end+String.(length "=")) 4 (* TODO catch exception *)
  |> Nocrypto.Base64.decode
  |> R.of_option ~none:(fun()-> Error `Invalid)
  >>= fun target_crc ->

  let out_buf = Cs.(create ((body_end - header_end)/4*3)) in
  let rec fill_out_buf offset decoded_offset =
    if offset >= body_end
    then Ok (Cs.sub out_buf 0 decoded_offset)
    else
    Cs.index buf ~offset ~max_offset:(min (offset+max_line_length) body_end) '\n'
    |> R.of_option ~none:(fun() -> Error `Invalid)
    >>= fun next_line ->
    let line_length = (next_line - offset) in
    Nocrypto.Base64.decode Cs.(sub buf offset line_length)
    |> R.of_option ~none:(fun() -> Error `Invalid)
    >>= fun decoded ->
    let decoded_len = Cs.len decoded in
    Cs.blit decoded 0 out_buf decoded_offset decoded_len
    ; fill_out_buf (next_line+1) (decoded_offset + decoded_len)
  in
  fill_out_buf header_end 0
  >>= fun decoded ->
  if Cs.equal (crc24 decoded) target_crc
  then Ok (pkt_type, decoded)
  else
    Error `Invalid_crc24

let parse_packet packet_tag pkt_body =
  begin match packet_tag with
    | Public_key -> Public_key_packet.parse_packet pkt_body
    | User_id -> Uid_packet.parse_packet pkt_body
    | Signature -> R.ok `Signature
  end

let next_packet (full_buf : Cs.t) :
  ((packet_type * Cs.t * Cs.t) option,
   [>`Invalid_packet
   | `Unimplemented_feature of string
   | `Incomplete_packet]) result =
  if Cs.len full_buf = 0 then Ok None else
  consume_packet_header full_buf
  |> R.reword_error (function
      |`Incomplete_packet as i -> i
      |`Invalid_packet_header -> `Invalid_packet)
  >>= begin function
  | { new_format ; length_type ; packet_tag } , pkt_header_tl ->
    consume_packet_length length_type pkt_header_tl
    |> R.reword_error (function
        | `Invalid_length -> `Invalid_packet
        | `Incomplete_packet as i -> i
        | `Unimplemented_feature_partial_length ->
      `Unimplemented_feature "partial length")
      >>= fun (pkt_body, next_packet) ->
      Ok (Some (packet_tag , pkt_body, next_packet))
  end
