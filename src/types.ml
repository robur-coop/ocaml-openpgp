open Rresult
open Usane

module type Keytype = sig
  type t
end

type public_key_algorithm =
  | RSA_encrypt_or_sign
  | RSA_sign_only
  | DSA

let public_key_algorithm_enum =
  (* RFC 4880: 9.1 Public-Key Algorithms *)
  [ '\001', RSA_encrypt_or_sign
  ; '\003', RSA_sign_only
  ; '\017', DSA
  ]

type ascii_packet_type =
  | Ascii_public_key_block
  | Ascii_private_key_block
  | Ascii_message
  | Ascii_message_part_x of {x : Uint16.t}
  | Ascii_message_part_x_of_y of {x:Uint16.t; y:Uint16.t}
  | Ascii_signature

let string_of_ascii_packet_type =
  begin function
    | Ascii_public_key_block -> "PUBLIC"
    | Ascii_private_key_block -> "PRIVATE"
    | Ascii_message -> "MESSAGE"
    | Ascii_message_part_x  n ->
       "MESSAGE, PART " ^ (string_of_int n.x)
    | Ascii_message_part_x_of_y  n ->
       "MESSAGE, PART "^(string_of_int n.x)^"/"^(string_of_int n.y)
    | Ascii_signature -> "SIGNATURE"
  end

type packet_type =
  | Signature
  | Secret_key
  | Public_key
  | Secret_subkey_packet
  | User_id
  | Public_key_subpacket

(* see RFC 4880: 4.3 Packet Tags *)
let packet_enum =
  (* note that in OCaml \XXX is decimal, not octal *)
  [ (* '\001', Public-Key Encrypted Session Key Packet *)
    ('\002', Signature)
    (* '\003', Symmetric-Key Encrypted Session Key Packet*)
    (* '\004', One-Pass Signature Packet *)
  ; ('\005', Secret_key)
  ; ('\006', Public_key)
  ; ('\007', Secret_subkey_packet)
    (* '\008', Compressed Data Packet *)
    (* '\009', Symmetrically Encrypted Data Packet *)
    (* '\010', Marker Packet *)
    (* '\011', Literal Data Packet *)
    (* '\012', Trust Packet *)
  ; ('\013', User_id)
  ; ('\014', Public_key_subpacket)
    (* '\017', User Attribute Packet *)
    (* '\018', Symmetrically Encrypted and Integrity Protected Data Packet *)
    (* '\019', Modification Detection Code Packet *)
  ]

type search_enum =
  | Enum_value
  | Enum_sumtype

let rec find_enum_value needle = function
| [] -> Error `Unmatched_enum_sumtype
| (value, sumtype)::_ when sumtype = needle -> Ok value
| _::tl -> find_enum_value needle tl

let rec find_enum_sumtype needle = function
| [] -> Error `Unmatched_enum_value
| (value, sumtype)::_ when value = needle -> Ok sumtype
| _::tl -> find_enum_sumtype needle tl

let packet_type_of_char needle =
  find_enum_sumtype needle packet_enum

let int_of_packet_type (needle:packet_type) =
  (find_enum_value needle packet_enum
  >>= fun c -> Ok (int_of_char c)
  ) |> R.get_ok

let public_key_algorithm_of_char needle =
  find_enum_sumtype needle public_key_algorithm_enum

let char_of_public_key_algorithm needle =
  find_enum_value needle public_key_algorithm_enum
  |> R.get_ok

let int_of_public_key_algorithm needle =
  char_of_public_key_algorithm needle |> int_of_char

let mpi_len buf : (Uint16.t, 'error) result =
  (* big-endian 16-bit integer len *)
  let rec search byte_offset =
    if byte_offset = Cs.len buf then R.ok Uint16.(of_int 0)
    else
      Cs.(get_uint8_result buf byte_offset)
      >>= fun c ->
      let rec bits_not_set =
        begin function
        | i when 0 <> (c land (1 lsl i)) -> Some (7-i)
        | 0 -> None
        | i -> bits_not_set (pred i)
        end
      in
      begin match bits_not_set 7 with
        | None -> search (succ byte_offset)
        | Some i -> Cs.(len buf)*8 - (byte_offset * 8) - i
                    |> Uint16.of_int |> R.ok
      end
  in
  search 0

let consume_mpi buf : (Z.t * Cs.t, 'error) result =
  (*
   Multiprecision integers (also called MPIs) are unsigned integers used
   to hold large integers such as the ones used in cryptographic
   calculations.

   An MPI consists of two pieces: a two-octet scalar that is the length
   of the MPI in bits followed by a string of octets that contain the
   actual integer.
  *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf 0
  >>= fun bitlen ->
  let bytelen = (bitlen + 7) / 8 in
  Cs.e_split ~start:2 `Incomplete_packet buf bytelen
  >>= fun (this_mpi , buf_tl) ->

  let reverse_cs cs : string =
  (* Zarith hides the function for reading little-endian unsigned integers under
     the name "to_bits".
     In the spirit of wasting time, the author(s) encourages
     kindly doing your own bloody string reversing if you want to
     use Zarith for real-world protocols: *)
    let out_buf = Buffer.create (Cstruct.len cs) in
      (for i = Cstruct.(len cs)-1 downto 0 do
        Buffer.add_char out_buf Cstruct.(get_char cs i)
      done ; Buffer.contents out_buf)
  in
  R.ok ((Z.of_bits (reverse_cs this_mpi)), buf_tl)

let crc24 (buf : Cs.t) : Cstruct.t =
(* adopted from the C reference implementation in RFC 4880:
    crc24 crc_octets(unsigned char *octets, size_t len)
*)
  let open Int32 in
  let (<<>) = shift_left in
  (*     while (len--) { *)
  let rec loop (len:int) (prev_crc:int32) =
    if len = Cstruct.len buf
    then prev_crc
    else
      (*        crc ^= ( *octets++) << 16; *)
      let c2 = Cstruct.get_char buf len
              |> int_of_char
              |> of_int
              |> fun c -> c <<> 16
              |> logxor prev_crc
      in
      (*        for (i = 0; i < 8; i++) { *)
      let rec inner_loop c3 = function
        | 8 -> c3
        | i ->
          (*        crc <<= 1; *)
          let c4 = c3 <<> 1 in
          (*        if (crc & 0x1000000) *)
          begin match 0_l <> logand c4 0x1_00_00_00_l with
          (*            crc ^= CRC24_POLY; *)
          | true -> let c5 = logxor c4 0x1_86_4c_fb_l in
                    inner_loop c5 (i+1)
          | false -> inner_loop c4 (i+1)
          end
      in
      let c6 = inner_loop c2 0 in
      loop (len+1) c6
  in
  (*        crc24 crc = CRC24_INIT; *)
  let cs = loop 0 0xB7_04_CE_l in
  let output = Cstruct.create 3 in
  for i = 0 to 2 do
    (* (cs & (0xff << bit_offset)) >> bit_offset *)
    let bit_offset = (2-i) * 8 in
    shift_right (logand cs (0xff_l <<> bit_offset)) bit_offset
    |> to_int
    |> Char.chr
    |> Cstruct.set_char output i
  done
  ; output

type packet_length_type =
  | One_octet
  | Two_octet
  | Four_octet
  | Partial_length

let packet_length_type_enum =
  [ (0 , One_octet)
  ; (1 , Two_octet)
  ; (2 , Four_octet)
  ; (3 , Partial_length)
  ]

let packet_length_type_of_size (size : Usane.Uint32.t) =
  begin match size with
  | s when -1 = Uint32.compare s 192l -> One_octet
  | s when -1 = Uint32.compare s 8384l -> Two_octet
  | _ -> Four_octet
  end

let int_of_packet_length_type needle =
  find_enum_value needle packet_length_type_enum
  |> R.get_ok

let packet_length_type_of_int needle = find_enum_sumtype needle packet_length_type_enum

let consume_packet_length length_type buf : ((Cs.t * Cs.t), [`Invalid_length | `Incomplete_packet | `Unimplemented_feature_partial_length]) result =
  (* see https://tools.ietf.org/html/rfc4880#section-4.2.2 *)
  Cs.e_get_char `Incomplete_packet buf 0
  >>= fun first_c ->
  let first = int_of_char first_c in
  let consume_old_packet_length : packet_length_type -> (int *Uint32.t, [`Invalid_length | `Incomplete_packet | `Unimplemented_feature_partial_length])result =
    begin function
      | One_octet -> R.ok (1, Uint32.of_int first)
      | Two_octet ->
        Cs.BE.e_get_uint16 `Incomplete_packet buf 0
        >>= fun length -> R.ok (2, Uint32.of_int length)
      | Four_octet ->
        Cs.BE.e_get_uint32 `Incomplete_packet buf 0
        >>= fun length -> R.ok (4, (length :> Uint32.t))
      | Partial_length ->
        R.error `Unimplemented_feature_partial_length
    end
  in
  let consume_new_packet_length =
  begin function
  | ('\000'..'\191') ->
     (* accomodate old+new format-style 1-octet lengths *)
     Ok (1 , Uint32.of_int first)
  | ('\192'..'\223') ->
      Cs.get_uint8_result buf 1
      |> R.reword_error (function _ -> `Invalid_length)
      >>= fun second ->
      Ok (2 , Uint32.of_int @@ ((first - 192) lsl 8) + second + 192)
  | ('\224'..'\254') ->
     Error `Unimplemented_feature_partial_length
  | '\255' ->
      Cs.BE.get_uint32 buf 1
      |> R.reword_error (function _ -> `Invalid_length)
      >>= fun length -> R.ok (5, length)
  end
  in
  begin match length_type with
    | None -> consume_new_packet_length first_c
    | Some typ -> consume_old_packet_length typ
  end
  >>= fun (start , length) ->
  match Uint32.to_int length with
  | Some length ->
    Cs.split_result ~start buf length
    |> R.reword_error (function _ ->  `Incomplete_packet)
  | None -> Error `Invalid_length

(* https://tools.ietf.org/html/rfc4880#section-4.2 : Packet Headers *)
type packet_header =
  { length_type : packet_length_type option
  ; packet_tag  : packet_type
  ; new_format  : bool
  }

let char_of_packet_header ph : (char,'error) result =
  begin match ph with
    | {new_format ; packet_tag; _} when new_format = true ->
      (1 lsl 6) lor (* 1 bit, new_format = true *)
      (int_of_packet_type packet_tag) (* 6 bits*)
      |> R.ok
    | {new_format; packet_tag; length_type = Some length_type;} when new_format = false ->
      ((int_of_packet_length_type length_type) land 0x3) (* 2 bits *)
      lor (((int_of_packet_type packet_tag) land 0xf) lsl 2) (* 4 bits *)
      |> R.ok
  | _ -> R.error `Invalid_packet_header
  end
  >>= fun pt ->
    pt lor (1 lsl 7) (* always one, 1 bit *)
    |> Char.chr |> R.ok

let packet_header_of_char (c : char) : (packet_header,'error) result =
  let bit_7_set x = x land (1 lsl 7) <> 0 in
  let bit_6_set x = x land (1 lsl 6) <> 0 in
  let bits_5_through_2 x = (x land (32 lor 16 lor 8 lor 4)) lsr 2 in
  let bits_1_through_0 x = x land (1 lor 2) in
  let bits_5_through_0 x = x land (64-1) in
  let c_int = int_of_char c in
  let new_format = bit_6_set c_int in
  if not (bit_7_set c_int)
  then Error `Invalid_packet_header
  else
  begin match new_format with
  | true ->
      bits_5_through_0 c_int |> Char.chr
      |> packet_type_of_char
      >>= fun pt -> R.ok (pt, None)
  | false ->
      packet_type_of_char (Char.chr (bits_5_through_2 c_int))
      >>= fun packet_tag ->
      let length_type = bits_1_through_0 c_int
                     |> packet_length_type_of_int
                     |> R.get_ok
      in R.ok (packet_tag, Some length_type)
  end
  >>= fun (packet_tag , length_type) ->
  Ok { length_type
     ; packet_tag
     ; new_format
  }

let consume_packet_header buf : ((packet_header * Cs.t), [`Invalid_packet_header | `Incomplete_packet]) result =
  Cs.e_split `Incomplete_packet buf 1
  >>= fun (header_buf , buf_tl) ->
  Cs.e_get_char `Incomplete_packet header_buf 0
  >>= fun c ->
  packet_header_of_char c
  |> R.reword_error (function _ -> `Invalid_packet_header)
  >>= fun pkt_header ->
  Ok (pkt_header , buf_tl)

(*
let generate_rsa size =
  let () = Nocrypto.Rng.reseed Cstruct.(of_string "abc") in (* TODO *)
  let priv = Nocrypto.Rsa.generate 1024 in (* TODO *)
  (*let pub = Nocrypto.Rsa.pub_of_priv priv in*)
*)
(*
let () =
  Printf.printf "foo\n%!";
  let a = Cstruct.of_string "abcyolanda" in
  let x = crc24 a in
  Printf.printf ":%s:\n" Cstruct.(to_string x)
 *)

module type Packet_type_S =
  sig
    type t
    val deserialize : Cs.t -> (t, 'error) result
    val serialize : t -> (Cs.t, 'error) result
    val tags : packet_type list
  end
