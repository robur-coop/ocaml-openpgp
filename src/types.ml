open Rresult
open Usane

module type Keytype = sig
  type t
end

type public_key_algorithm =
  | RSA_encrypt_or_sign
  | RSA_sign_only
  | Elgamal_encrypt_only
  | DSA

let public_key_algorithm_enum =
  (* RFC 4880: 9.1 Public-Key Algorithms *)
  [ '\001', RSA_encrypt_or_sign
  ; '\003', RSA_sign_only
  ; '\016', Elgamal_encrypt_only
  ; '\017', DSA
  ]

type mpi = Z.t

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

type packet_tag_type =
  | Signature_tag
  | Secret_key_tag
  | Public_key_tag
  | Secret_subkey_packet_tag
  | Uid_tag
  | User_attribute_tag
  | Public_key_subpacket_tag

(* see RFC 4880: 4.3 Packet Tags *)
let packet_tag_enum =
  (* note that in OCaml \XXX is decimal, not octal *)
  [ (* '\001', Public-Key Encrypted Session Key Packet *)
    ('\002', Signature_tag)
    (* '\003', Symmetric-Key Encrypted Session Key Packet*)
    (* '\004', One-Pass Signature Packet *)
  ; ('\005', Secret_key_tag)
  ; ('\006', Public_key_tag)
  ; ('\007', Secret_subkey_packet_tag)
    (* '\008', Compressed Data Packet *)
    (* '\009', Symmetrically Encrypted Data Packet *)
    (* '\010', Marker Packet *)
    (* '\011', Literal Data Packet *)
    (* '\012', Trust Packet *)
  ; ('\013', Uid_tag)
  ; ('\014', Public_key_subpacket_tag)
  ; '\017', User_attribute_tag (*User Attribute Packet *)
    (* '\018', Symmetrically Encrypted and Integrity Protected Data Packet *)
    (* '\019', Modification Detection Code Packet *)
  ]

type signature_type =
  (* RFC 4880: 5.2.1 Signature Types *)
  | Signature_of_binary_document
  | Signature_of_canonical_text_document
  | Standalone_signature
  | Generic_certification_of_user_id_and_public_key_packet
  | Persona_certification_of_user_id_and_public_key_packet
  | Casual_certification_of_user_id_and_public_key_packet
  | Positive_certification_of_user_id_and_public_key_packet
  | Subkey_binding_signature
  | Primary_key_binding_signature
  | Signature_directly_on_key
  | Key_revocation_signature
  | Subkey_revocation_signature
  | Certification_revocation_signature
  | Timestamp_signature
  | Third_party_confirmation_signature

let signature_type_enum =
   [ '\x00', Signature_of_binary_document
  ; '\x01', Signature_of_canonical_text_document
  ; '\x02', Standalone_signature
  ; '\x10', Generic_certification_of_user_id_and_public_key_packet
  ; '\x11', Persona_certification_of_user_id_and_public_key_packet
  ; '\x12', Casual_certification_of_user_id_and_public_key_packet
  ; '\x13', Positive_certification_of_user_id_and_public_key_packet
  ; '\x18', Subkey_binding_signature
  ; '\x19', Primary_key_binding_signature
  ; '\x1f', Signature_directly_on_key
  ; '\x20', Key_revocation_signature
  ; '\x28', Subkey_revocation_signature
  ; '\x30', Certification_revocation_signature
    ; '\x40', Timestamp_signature
    ; '\x50', Third_party_confirmation_signature
  ]

type signature_subpacket_type =
  | Signature_creation_time
  | Signature_expiration_time
  | Exportable_certification
  | Trust_signature
  | Regular_expression
  | Revocable
  | Key_expiration_time
  | Preferred_symmetric_algorithms
  | Revocation_key
  | Issuer
  | Notation_data
  | Preferred_hash_algorithms
  | Preferred_compression_algorithms
  | Key_server_preferences
  | Preferred_key_server
  | Primary_user_id
  | Policy_URI
  | Key_flags
  | Signers_user_id
  | Reason_for_revocation
  | Features
  | Signature_target
  | Embedded_signature

type hash_algorithm =
  (* RFC 4880: 9.4 Hash Algorithms *)
  | MD5
  | SHA1
  | SHA256
  | SHA384
  | SHA512
  | SHA224
  (* TODO RIPE-MD/160 *)

let nocrypto_module_of_hash_algorithm : hash_algorithm -> (module Nocrypto.Hash.S) =
  begin function
    | MD5 -> (module Nocrypto.Hash.MD5)
    | SHA1 -> (module Nocrypto.Hash.SHA1)
    | SHA256 -> (module Nocrypto.Hash.SHA256)
    | SHA384 -> (module Nocrypto.Hash.SHA384)
    | SHA512 -> (module Nocrypto.Hash.SHA512)
    | SHA224 -> (module Nocrypto.Hash.SHA224)
  end

let hash_algorithm_enum =
  [ '\001', MD5
  ; '\002', SHA1
  ; '\008', SHA256
  ; '\009', SHA384
  ; '\010', SHA512
  ; '\011', SHA224
  ]

type search_enum =
  | Enum_value
  | Enum_sumtype

(* TODO consider just failwith if not matched *)
let rec find_enum_value needle = function
| [] -> Error `Unmatched_enum_sumtype
| (value, sumtype)::_ when sumtype = needle -> Ok value
| _::tl -> find_enum_value needle tl

let rec find_enum_sumtype needle = function
| [] -> Error `Unmatched_enum_value
| (value, sumtype)::_ when value = needle -> Ok sumtype
| _::tl -> find_enum_sumtype needle tl

let packet_tag_type_of_char needle =
  find_enum_sumtype needle packet_tag_enum

let int_of_packet_tag_type (needle:packet_tag_type) =
  (find_enum_value needle packet_tag_enum
  >>= fun c -> Ok (int_of_char c)
  ) |> R.get_ok

let public_key_algorithm_of_char needle =
  find_enum_sumtype needle public_key_algorithm_enum
  |> R.reword_error (function _ -> `Unimplemented_algorithm needle)

let public_key_algorithm_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset
  >>= fun pk_algo_c ->
  public_key_algorithm_of_char pk_algo_c

let char_of_public_key_algorithm needle =
  find_enum_value needle public_key_algorithm_enum
  |> R.get_ok

let int_of_public_key_algorithm needle =
  char_of_public_key_algorithm needle |> int_of_char

let char_of_signature_type needle =
  find_enum_value needle signature_type_enum |> R.get_ok

let signature_type_of_char needle =
  find_enum_sumtype needle signature_type_enum
  |> R.reword_error (function _ -> `Unimplemented_algorithm needle)

let signature_type_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset
  >>= fun signature_type_c ->
  signature_type_of_char signature_type_c

let hash_algorithm_of_char needle =
  find_enum_sumtype needle hash_algorithm_enum
  |> R.reword_error (function _ -> `Unimplemented_algorithm needle)

let hash_algorithm_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset
  >>= fun hash_algo_c ->
  hash_algorithm_of_char hash_algo_c

let char_of_hash_algorithm needle =
  find_enum_value needle hash_algorithm_enum |> R.get_ok

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

let cs_of_mpi_no_header mpi : Cs.t =
  Z.to_bits mpi
  |> Cs.of_string
  (* TODO |> strip trailing section of nullbytes *)
  |> Cs.reverse

let cs_of_mpi mpi : (Cs.t, 'error) result =
  let mpi_body = cs_of_mpi_no_header mpi in
  mpi_len mpi_body >>= fun body_len ->
  let mpi_header = Cs.create 2 in
  Cs.BE.set_uint16 mpi_header 0 body_len
  >>= fun mpi_header ->
  R.ok (Cs.concat [mpi_header; mpi_body])

let consume_mpi buf : (mpi * Cs.t, 'error) result =
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
  let()= Printf.printf "going to read%d %S\n" bytelen (Cs.to_string buf) in
  Cs.e_split ~start:2 `Incomplete_packet buf bytelen
  >>= fun (this_mpi , buf_tl) ->
  R.ok ((Z.of_bits (Cs.reverse this_mpi |> Cs.to_string)), buf_tl)

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
  ; packet_tag  : packet_tag_type
  ; new_format  : bool
  }

let char_of_packet_header ph : (char,'error) result =
  begin match ph with
    | {new_format ; packet_tag; _} when new_format = true ->
      (1 lsl 6) lor (* 1 bit, new_format = true *)
      (int_of_packet_tag_type packet_tag) (* 6 bits*)
      |> R.ok
    | {new_format; packet_tag; length_type = Some length_type;} when new_format = false ->
      ((int_of_packet_length_type length_type) land 0x3) (* 2 bits *)
      lor (((int_of_packet_tag_type packet_tag) land 0xf) lsl 2) (* 4 bits *)
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
      |> packet_tag_type_of_char
      >>= fun pt -> R.ok (pt, None)
  | false ->
      packet_tag_type_of_char (Char.chr (bits_5_through_2 c_int))
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

let v4_verify_version (buf : Cs.t) :
  (unit ,
   [> `Unimplemented_version of char
   | `Incomplete_packet]) result =
  Cs.e_get_char `Incomplete_packet buf 0
  >>= fun version ->
  if version <> '\x04' then
    R.error (`Unimplemented_version version)
  else
    R.ok ()

let dsa_asf_are_valid_parameters ~(p:Z.t) ~(q:Z.t) ~hash_algo =
  (* From RFC 4880 (we whitelist these parameters): *)
  (*   DSA keys MUST also be a multiple of 64 bits, *)
  (*   and the q size MUST be a multiple of 8 bits. *)
  (*   1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash *)
  (*   2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash *)
  (*   2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash *)
  (*   3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash *)
  begin match Z.numbits p , Z.numbits q, hash_algo with
    | 1024 , 160 ,(SHA1|SHA224|SHA256|SHA384|SHA512) ->
        R.ok ()
    | 2048 , 224 ,(SHA224|SHA256|SHA384|SHA512) -> R.ok ()
    | (2048|3072), 256 ,(SHA256|SHA384|SHA512) -> R.ok ()
    | _ , _ , _ -> R.error `Nonstandard_DSA_parameters
  end
