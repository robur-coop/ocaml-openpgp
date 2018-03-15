open Rresult
open Usane

let list_find_leading (f : 'a -> ('b,'c) result) (lst : 'a list)
  : ('d list, 'error) result =
  let rec loop acc = function
    | m::tl ->
      begin match f m with
        | Ok value -> loop (value::acc) tl
        | Error _ -> loop acc []
      end
    | [] -> R.ok (List.rev acc)
  in
  loop [] lst

let list_find_leading_pairs (f : 'a -> 'a -> ('c,'err) result) (lst : 'a list)
  : ('c list, 'err) result =
  let rec loop acc = function
    | a::b::tl ->
      begin match f a b with
        | Ok x -> loop (x::acc) tl
        | Error _ -> R.ok (List.rev acc)
      end
    | ([]|(_::_)) -> R.ok (List.rev acc)
  in
  loop [] lst

let list_drop_e_n (err : 'error) n lst : ('a list,'error) result =
  let rec loop i = function
    | tl when i <= 0 -> R.ok tl
    | _::tl -> loop (i-1) tl
    | [] -> R.error err
  in
  loop n lst;;

let list_take_leading f lst : ('a list * 'b list, 'error) result =
  list_find_leading f lst >>= fun left ->
  Ok (left, list_drop_e_n `Guarded (List.length left) lst |> R.get_ok)

let result_ok_list_or_error (parser : 'a -> ('b,'c) result) (body_lst : 'a list) =
  (* TODO perhaps this function should be called concat_result or similar *)
  List.fold_left (fun acc -> fun cs ->
            acc >>= fun acc ->
            parser cs >>= fun parsed ->
            R.ok (parsed::acc)
    ) (Ok []) body_lst >>| List.rev

let result_filter f lst =
  (* List.filter returning the elements with Ok results *)
  Ok (List.filter (fun e -> match f e with Ok _ -> true | _ -> false) lst)

let e_char_equal e c c2 = if c <> c2 then Error e else Ok c

(* The polymorphic error type helps you define wrapper around error_msg: *)
type ('a,'b,'c,'return) value_msg =
  ( ('a, Format.formatter, unit,'b) format4 -> 'c) -> 'return
type ('a,'b,'c,'return,'err) msg_err =
  ('a,'b,'c,('return,
             ([> `Msg of string] as 'err)
            ) result ) value_msg

let level_msg level (params : ('a,'b,'c,[>`Msg of string]) value_msg) =
  params @@ Fmt.kstrf (fun a -> Logs.msg level (fun m -> m "%a" Fmt.text a) ;
                       `Msg a)
let err_msg_debug log = Error (level_msg Logs.Debug log)
let error_msg log = Error (level_msg Logs.Error log)
  (* <error_msg (fun m -> m "foo:%d" 123)> is <Error (`Msg "foo:123")>*)
let e_true e bool = if bool then Ok () else Error e
let true_or_error bool f : (unit,'t)result = if bool then Ok () else
    Error (level_msg Logs.Error f)
let log_msg log v = Logs.debug log ; v
let log_failed log = R.reword_error (log_msg log)
let replace_error log v = R.reword_error (fun _ -> level_msg Logs.Error log) v

let msg_of_error err =
  `Msg
  (match err with
  | `Incomplete_packet -> "incomplete packet"
  | `Extraneous_packets_after_signature -> "extraneous data after signature"
  | `Msg str -> str
  )

let pp_mpi = Z.pp_print

let msg_of_invalid_mpi_parameters mpi_list : [> `Msg of string ]=
  `Msg (Fmt.strf "Invalid MPIs:@[<v>%a@]" Fmt.(list ~sep:(unit "; ") pp_mpi)
                                          mpi_list)

let pp_error ppf err =
  match msg_of_error err with
  | `Msg msg -> Fmt.pf ppf "@[<v>%s@]" (msg)

type openpgp_version =
  | V3
  | V4

let pp_version ppf v =
  Fmt.string ppf @@ match v with
  | V3 -> "V3"
  | V4 -> "V4"

let char_of_version = function
  | V3 -> '\003'
  | V4 -> '\004'

let cs_of_version v = char_of_version v |> Cs.of_char

let e_version_of_char e = function
  | '\003' -> Ok V3
  | '\004' -> Ok V4
  | _ -> Error e

type feature =
  | Modification_detection
  | Unknown_feature of char

let pp_feature fmt feature =
  Fmt.string fmt @@ match feature with
  | Modification_detection -> "Modification Detection"
  | Unknown_feature c -> Cs.(to_hex @@ of_char c)

type hash_algorithm =
  (* RFC 4880: 9.4 Hash Algorithms *)
  | MD5
  | RIPEMD160
  | SHA1
  | SHA256
  | SHA384
  | SHA512
  | SHA224
  | Unknown_hash of char

let pp_hash_algorithm ppf v =
  Fmt.string ppf @@ match v with
  | MD5 -> "MD5"
  | RIPEMD160 -> "RIPE-MD/160"
  | SHA1 -> "SHA1"
  | SHA256 -> "SHA256"
  | SHA384 -> "SHA384"
  | SHA512 -> "SHA512"
  | SHA224 -> "SHA224"
  | Unknown_hash c -> Format.sprintf "Unknown[%02x]" (Char.code c)

type public_key_algorithm =
  | RSA_encrypt_or_sign
  | RSA_encrypt_only
  | RSA_sign_only
  | Elgamal_encrypt_only
  | DSA

let public_key_algorithm_of_string algo =
  match String.lowercase_ascii algo with
  | "rsa" -> Ok RSA_encrypt_or_sign
  | "dsa" -> Ok DSA
  | _ -> error_msg (fun m -> m "of_string: unknown pk algorithm: \"%S\"" algo)

let pp_public_key_algorithm ppf a =
  Fmt.string ppf @@ match a with
  | RSA_encrypt_or_sign -> "RSA encrypt or sign"
  | RSA_encrypt_only -> "RSA encrypt"
  | RSA_sign_only -> "RSA sign"
  | Elgamal_encrypt_only -> "ElGamal encrypt"
  | DSA -> "DSA"

let public_key_algorithm_enum =
  (* RFC 4880: 9.1 Public-Key Algorithms *)
  [ '\001', RSA_encrypt_or_sign
  ; '\002', RSA_encrypt_only
  ; '\003', RSA_sign_only
  ; '\016', Elgamal_encrypt_only
  ; '\017', DSA
  ]

type symmetric_algorithm =
  | AES128
  | AES192
  | AES256
  | Unknown_encryption of char

let symmetric_algorithm_enum =
  [ '\007', AES128
  ; '\008', AES192
  ; '\009', AES256
  ]

let pp_symmetric_algorithm ppf v =
  Fmt.string ppf @@ match v with
  | AES128 -> "AES-128"
  | AES192 -> "AES-192"
  | AES256 -> "AES-256"
  | Unknown_encryption c ->
    Format.sprintf "Unknown[%02x]" (Char.code c)

type mpi = Z.t

type ascii_packet_type =
  | Ascii_public_key_block
  | Ascii_private_key_block
  | Ascii_message
  | Ascii_message_part_x of {x : Uint16.t}
  | Ascii_message_part_x_of_y of {x:Uint16.t; y:Uint16.t}
  | Ascii_signature

let pp_ascii_packet_type ppf = function
  | Ascii_public_key_block -> Fmt.pf ppf "ASCII public key block"
  | Ascii_private_key_block -> Fmt.pf ppf "ASCII private key block"
  | Ascii_message -> Fmt.pf ppf "ASCII message"
  | Ascii_message_part_x n -> Fmt.pf ppf "ASCII message part %d" n.x
  | Ascii_message_part_x_of_y n -> Fmt.pf ppf "ASCII message part %d/%d" n.x n.y
  | Ascii_signature -> Fmt.pf ppf "ASCII signature"

let string_of_ascii_packet_type = function
  | Ascii_public_key_block -> "PUBLIC KEY BLOCK"
  | Ascii_private_key_block -> "PRIVATE KEY BLOCK"
  | Ascii_message -> "MESSAGE"
  | Ascii_message_part_x n -> "MESSAGE, PART " ^ string_of_int n.x
  | Ascii_message_part_x_of_y n ->
    "MESSAGE, PART " ^ string_of_int n.x ^ "/" ^ string_of_int n.y
  | Ascii_signature -> "SIGNATURE"

type packet_tag_type =
  | Signature_tag
  | Secret_key_tag
  | Public_key_tag
  | Secret_subkey_tag
  | Uid_tag
  | Public_subkey_tag
  | User_attribute_tag
  | Trust_packet_tag
  | Encrypted_packet_tag
  | Public_key_encrypted_session_packet_tag

let pp_packet_tag ppf v =
  Fmt.string ppf @@ match v with
  | Signature_tag -> "signature"
  | Secret_key_tag -> "secret key"
  | Public_key_tag -> "public key"
  | Secret_subkey_tag -> "secret subkey"
  | Uid_tag -> "uid"
  | Public_subkey_tag -> "public subkey"
  | User_attribute_tag -> "user attribute"
  | Trust_packet_tag -> "trust packet"
  | Encrypted_packet_tag -> "Encrypted packet"
  | Public_key_encrypted_session_packet_tag ->
    "Public-Key encrypted session packet"

(* see RFC 4880: 4.3 Packet Tags *)
let packet_tag_enum =
  (* note that in OCaml \XXX is decimal, not octal *)
  [ ('\001', Public_key_encrypted_session_packet_tag)
  ; ('\002', Signature_tag)
    (* '\003', Symmetric-Key Encrypted Session Key Packet*)
    (* '\004', One-Pass Signature Packet *)
  ; ('\005', Secret_key_tag)
  ; ('\006', Public_key_tag)
  ; ('\007', Secret_subkey_tag)
    (* '\008', Compressed Data Packet *)
    (* '\009', Symmetrically Encrypted Data Packet *)
    (* '\010', Marker Packet *)
  (* '\011', Literal Data Packet *) (*TODO*)
  ; '\012', Trust_packet_tag
  ; '\013', Uid_tag
  ; '\014', Public_subkey_tag
  ; '\017', User_attribute_tag (*User Attribute Packet *)
  ; '\018', Encrypted_packet_tag
  (* ^-- Symmetrically Encrypted and Integrity Protected Data Packet *)
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

let pp_signature_type ppf v =
  Fmt.string ppf @@ match v with
  | Signature_of_binary_document -> "binary document"
  | Signature_of_canonical_text_document -> "canonical text"
  | Standalone_signature -> "standalone"
  | Generic_certification_of_user_id_and_public_key_packet ->
    "generic certification of uid and public key"
  | Persona_certification_of_user_id_and_public_key_packet ->
    "persona certification of uid and public key"
  | Casual_certification_of_user_id_and_public_key_packet ->
    "persona certification of uid and public key"
  | Positive_certification_of_user_id_and_public_key_packet ->
    "positive certification of uid and public key"
  | Subkey_binding_signature -> "subkey binding"
  | Primary_key_binding_signature -> "primary key"
  | Signature_directly_on_key -> "signature directly on key"
  | Key_revocation_signature -> "key revocation"
  | Subkey_revocation_signature -> "subkey revocation"
  | Certification_revocation_signature -> "certification revocation"
  | Timestamp_signature -> "timestamp"
  | Third_party_confirmation_signature -> "third party confirmation"

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

type key_usage_flags = (* RFC 4880: 5.2.3.21 Key Flags *)
  { certify_keys : bool
  ; sign_data : bool
  ; encrypt_communications : bool
  ; encrypt_storage : bool
  ; authentication : bool
  ; unimplemented : char
  }

let empty_key_usage_flags =
  { certify_keys = false; sign_data = false; encrypt_communications = false;
    encrypt_storage = false; authentication = false; unimplemented = '\000'; }

let key_usage_flags_of_char needle =
  let n = Char.code needle in
  let bit place = 0 <> n land (1 lsl place) in
  { certify_keys = bit 0
  ; sign_data    = bit 1
  ; encrypt_communications = bit 2
  ; encrypt_storage = bit 3
  (* ; whatever = bit 4 *)
  ; authentication = bit 5
  ; unimplemented = needle
  }

let char_of_key_usage_flags t =
  let bit place = function
    | false -> 0
    | true -> 1 lsl place
  in
  [ Char.code t.unimplemented
  ; bit 0 t.certify_keys
  ; bit 1 t.sign_data
  ; bit 2 t.encrypt_communications
  ; bit 3 t.encrypt_storage
  (*; bit 4 some-other-thing-not-implemented *)
  ; bit 5 t.authentication
  ] |> List.fold_left (lor) 0
  |> Char.chr

let cs_of_key_usage_flags t = char_of_key_usage_flags t |> Cs.of_char

type signature_subpacket_tag =
  | Signature_creation_time
  | Signature_expiration_time
  | Exportable_certification
  | Trust_signature
  | Regular_expression
  | Revocable
  | Key_expiration_time
  | Preferred_symmetric_algorithms
  | Revocation_key
  | Issuer_keyid
  | Notation_data
  | Preferred_hash_algorithms
  | Preferred_compression_algorithms
  | Key_server_preferences
  | Preferred_key_server
  | Primary_user_id
  | Policy_URI
  | Key_usage_flags
  | Signers_user_id
  | Reason_for_revocation
  | Features
  | Signature_target
  | Embedded_signature
  | Issuer_fingerprint
  | Unimplemented_signature_subpacket_tag of char

type signature_subpacket_ptag =
  [ `Signature_creation_time
  | `Signature_expiration_time
  | `Exportable_certification
  | `Trust_signature
  | `Regular_expression
  | `Revocable
  | `Key_expiration_time
  | `Preferred_symmetric_algorithms
  | `Revocation_key
  | `Issuer_keyid
  | `Notation_data
  | `Preferred_hash_algorithms
  | `Preferred_compression_algorithms
  | `Key_server_preferences
  | `Preferred_key_server
  | `Primary_user_id
  | `Policy_URI
  | `Key_usage_flags
  | `Signers_user_id
  | `Reason_for_revocation
  | `Features
  | `Signature_target
  | `Embedded_signature
  | `Issuer_fingerprint
  | `Unimplemented_signature_subpacket_tag of char
  ]

let pp_signature_subpacket_tag ppf v =
  Fmt.string ppf @@
    begin match v with
    | Signature_creation_time -> "Signature_creation_time"
    | Signature_expiration_time -> "Signature_expiration_time"
    | Exportable_certification -> "Exportable_certification"
    | Trust_signature -> "Trust_signature"
    | Regular_expression -> "Regular_expression"
    | Revocable -> "Revocable"
    | Key_expiration_time -> "Key expiration time"
    | Preferred_symmetric_algorithms -> "Preferred_symmetric_algorithms"
    | Revocation_key -> "Revocation_key"
    | Issuer_keyid -> "Issuer key ID"
    | Notation_data -> "Notation_data"
    | Preferred_hash_algorithms -> "Preferred_hash_algorithms"
    | Preferred_compression_algorithms -> "Preferred_compression_algorithms"
    | Key_server_preferences -> "Key_server_preferences"
    | Preferred_key_server -> "Preferred_key_server"
    | Primary_user_id -> "Primary_user_id"
    | Policy_URI -> "Policy_URI"
    | Key_usage_flags -> "Key_usage_flags"
    | Signers_user_id -> "Signers_user_id"
    | Reason_for_revocation -> "Reason_for_revocation"
    | Features -> "Features"
    | Signature_target -> "Signature_target"
    | Embedded_signature -> "Embedded_signature"
    | Issuer_fingerprint -> "Issuer_fingerprint"
    | Unimplemented_signature_subpacket_tag c ->
      Format.sprintf "(Unimplemented subpacket tag: %02x)" (Char.code c)
    end

let signature_subpacket_tag_enum = (*in gnupg this is enum sigsubpkttype_t *)
  [ '\002', Signature_creation_time
  ; '\003', Signature_expiration_time
  ; '\004', Exportable_certification
  ; '\005', Trust_signature
  ; '\006', Regular_expression
  ; '\007', Revocable
  ; '\009', Key_expiration_time
  ; '\011', Preferred_symmetric_algorithms
  ; '\012', Revocation_key
  ; '\016', Issuer_keyid
  ; '\020', Notation_data
  ; '\021', Preferred_hash_algorithms
  ; '\022', Preferred_compression_algorithms
  ; '\023', Key_server_preferences
  ; '\024', Preferred_key_server
  ; '\025', Primary_user_id
  ; '\026', Policy_URI
  ; '\027', Key_usage_flags
  ; '\028', Signers_user_id
  ; '\029', Reason_for_revocation
  ; '\030', Features
  ; '\031', Signature_target
  ; '\032', Embedded_signature
  ; '\033', Issuer_fingerprint (* This is not from RFC 4880, but it consists
                                * of a version char (04) and a SHA1 of the pk *)
  ]

let e_log_ptime_plus_span_is_smaller err_cb (base,span) current_time =
  Ptime.add_span base span |> R.of_option ~none:(fun () -> error_msg err_cb)
  >>| Ptime.compare current_time
  >>= fun comp ->
  true_or_error (-1 = comp) err_cb

let nocrypto_poly_variant_of_hash_algorithm = function
  | MD5 -> Error (`Msg "MD5 is deprecated and disabled for security reasons")
  | SHA1 -> Ok `SHA1
  | SHA224 -> Ok `SHA224
  | SHA256 -> Ok `SHA256
  | SHA384 -> Ok `SHA384
  | SHA512 -> Ok `SHA512
  | RIPEMD160 -> Error (`Msg "RIPE-MD/160 not implemented")
  | Unknown_hash c ->
    error_msg (fun m -> m "can't give unimplemented hash \
                           algorithm %d to nocrypto" (Char.code c))

let nocrypto_module_of_hash_algorithm algo :
  ((module Nocrypto.Hash.S),[> ]) result =
  nocrypto_poly_variant_of_hash_algorithm algo >>| Nocrypto.Hash.module_of

type digest_finalizer = unit -> Cs.t
type digest_feeder = (Cs.t -> unit) * digest_finalizer

let digest_callback hash_algo: (digest_feeder, [> ]) result =
  nocrypto_module_of_hash_algorithm hash_algo >>= fun m ->
  let module H = (val (m)) in
  let t = ref H.empty in
  let feeder cs = (t := H.feed !t (Cs.to_cstruct cs))
                  |> log_msg (fun m -> m "%a hashing %d bytes: %a\n"
                                 pp_hash_algorithm hash_algo
                                 (Cs.len cs) Cs.pp_hex cs)
  in Ok (feeder,
        (fun () -> H.get !t |> Cs.of_cstruct))

let compute_digest hash_algo to_be_hashed =
  digest_callback hash_algo >>= fun (feed, get) ->
  (feed to_be_hashed ; Ok (get ()))

let features_enum =
  [ '\001', Modification_detection
  ]

let hash_algorithm_enum =
  [ '\001', MD5
  ; '\002', SHA1
  ; '\003', RIPEMD160
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

let feature_of_char needle =
  find_enum_sumtype needle features_enum
  |>  R.ignore_error ~use:(fun `Unmatched_enum_value ->
      Logs.debug (fun m -> m "Unimplemented feature 0x%02x"
                     (Char.code needle));
      Unknown_feature needle
    )

let char_of_feature needle = find_enum_value needle features_enum |> R.get_ok

let hash_algorithm_of_char needle =
  find_enum_sumtype needle hash_algorithm_enum
  |> R.ignore_error ~use:(fun `Unmatched_enum_value ->
         Logs.debug (fun m -> m "Unimplemented hash algorithm 0x%02x"
               (Char.code needle));
         Unknown_hash needle
     )

let hash_algorithm_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset >>| hash_algorithm_of_char

let char_of_hash_algorithm needle =
  find_enum_value needle hash_algorithm_enum |> R.get_ok

let cs_of_hash_algorithm a = char_of_hash_algorithm a |> Cs.of_char

let char_of_symmetric_algorithm = function
  | Unknown_encryption c -> c
  | needle -> find_enum_value needle symmetric_algorithm_enum |> R.get_ok

let cs_of_symmetric_algorithm a = char_of_symmetric_algorithm a |> Cs.of_char

let symmetric_algorithm_of_char needle =
  find_enum_sumtype needle symmetric_algorithm_enum
  |> R.ignore_error ~use:(fun `Unmatched_enum_value ->
         Logs.debug (fun m -> m "Unimplemented symmetric algorithm 0x%02x"
               (Char.code needle));
         Unknown_encryption needle )

let packet_tag_type_of_char needle =
  find_enum_sumtype needle packet_tag_enum
  |> R.reword_error (fun `Unmatched_enum_value ->
                         `Msg "Invalid packet_tag_type")

let int_of_packet_tag_type (needle:packet_tag_type) =
  (find_enum_value needle packet_tag_enum >>= fun c ->
   Ok (int_of_char c)) |> R.get_ok

let public_key_algorithm_of_char needle =
  find_enum_sumtype needle public_key_algorithm_enum
  |> log_failed (fun m -> m "Unimplemented public key algorithm: %02x" (Char.code needle))
  |> R.reword_error (fun _ -> `Msg "Unimplemented public key algorithm")

let public_key_algorithm_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset >>= fun pk_algo_c ->
  public_key_algorithm_of_char pk_algo_c

let char_of_public_key_algorithm needle =
  find_enum_value needle public_key_algorithm_enum |> R.get_ok

let int_of_public_key_algorithm needle =
  char_of_public_key_algorithm needle |> int_of_char

let char_of_signature_type needle =
  find_enum_value needle signature_type_enum |> R.get_ok

let signature_type_of_char needle =
  find_enum_sumtype needle signature_type_enum
  |> log_failed (fun m -> m "Unimplemented signature type %02x" (Char.code needle))
  |> R.reword_error (fun _ -> `Msg "Unimplemented signature type algorithm")

let signature_type_of_cs_offset cs offset =
  Cs.e_get_char `Incomplete_packet cs offset
  >>= fun signature_type_c ->
  signature_type_of_char signature_type_c

let signature_subpacket_tag_of_char needle : signature_subpacket_tag =
  find_enum_sumtype needle signature_subpacket_tag_enum
  |> R.ignore_error ~use:(fun `Unmatched_enum_value ->
         Logs.debug (fun m -> m "Unimplemented signature subpacket type 0x%02x"
               (Char.code needle));
         Unimplemented_signature_subpacket_tag needle
     )

let char_of_signature_subpacket_tag = function
  | Unimplemented_signature_subpacket_tag c -> c
  | needle -> find_enum_value needle signature_subpacket_tag_enum |> R.get_ok

let cs_of_signature_subpacket_tag needle =
  char_of_signature_subpacket_tag needle |> String.make 1 |> Cs.of_string

let mpi_len buf : (Uint16.t, 'error) result =
  (* big-endian 16-bit integer len *)
  let rec search byte_offset =
    if byte_offset = Cs.len buf then
      R.ok Uint16.(of_int 0)
    else
      Cs.(get_uint8 buf byte_offset) >>= fun c ->
      let rec bits_not_set = function
          | i when 0 <> (c land (1 lsl i)) -> Some (7-i)
          | 0 -> None
          | i -> bits_not_set (pred i)
      in
      match bits_not_set 7 with
      | None -> search (succ byte_offset)
      | Some i -> Cs.(len buf)*8 - (byte_offset * 8) - i |> Uint16.of_int |> R.ok
  in
  search 0

let cs_of_mpi_no_header mpi : Cs.t =
  Z.to_bits mpi
  |> Cs.of_string
  (* TODO |> strip trailing section of nullbytes *)
  |> Cs.reverse
  |> Cs.strip_leading_char '\x00'

let mpis_are_prime lst =
  let non_primes =
    List.find_all (fun mpi -> not @@ Nocrypto.Numeric.pseudoprime mpi) lst
  in
  if non_primes <> [] then begin
    Logs.debug (fun m -> m "MPIs are not prime: %a"
                   Fmt.(list ~sep:(unit " ; ") Cs.pp_hex)
                   (List.map cs_of_mpi_no_header non_primes)) ;
    R.error (msg_of_invalid_mpi_parameters non_primes)
  end else R.ok ()

let cs_of_mpi mpi : (Cs.t, 'error) result =
  let mpi_body = cs_of_mpi_no_header mpi in
  mpi_len mpi_body >>= fun body_bitlen ->
  Logs.debug (fun m -> m "cs_of_mpi: %d: %a"
                 body_bitlen Cs.pp_hex mpi_body) ;
  let buf = Cs.W.create (2 + body_bitlen/8) in
  Cs.W.uint16 buf body_bitlen ;
  Cs.W.cs buf mpi_body ;
  Ok (Cs.W.to_cs buf)

let cs_of_mpi_list mpi_list =
  let rec loop acc = function
    | hd::tl -> cs_of_mpi hd >>= fun cs -> loop (cs::acc) tl
    | [] -> R.ok (List.rev acc |> Cs.concat)
  in
  loop [] mpi_list

let mpi_of_cs_no_header cs = Cs.reverse cs |> Cs.to_string |> Z.of_bits

let consume_mpi buf : (mpi * Cs.t, [> `Incomplete_packet ]) result =
  (*
   Multiprecision integers (also called MPIs) are unsigned integers used
   to hold large integers such as the ones used in cryptographic
   calculations.

   An MPI consists of two pieces: a two-octet scalar that is the length
   of the MPI in bits followed by a string of octets that contain the
   actual integer.
  *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf 0 >>= fun bitlen ->
  let bytelen = (bitlen + 7) / 8 in
  Logs.debug (fun m -> m "going to read %d:@.%a" bytelen Cs.pp_hex buf) ;
  Cs.e_split ~start:2 `Incomplete_packet buf bytelen >>= fun (this_mpi, tl) ->
  Logs.debug (fun m -> m "splitmpi");
  R.ok (mpi_of_cs_no_header this_mpi, tl)

let crc24 (buf : Cs.t) : Cs.t =
(* adopted from the C reference implementation in RFC 4880:
    crc24 crc_octets(unsigned char *octets, size_t len)
*)
  let open Int32 in
  let (<<>) = shift_left in
  (*     while (len--) { *)
  let rec loop (len:int) (prev_crc:int32) =
    if len = Cs.len buf then
      prev_crc
    else
      (*        crc ^= ( *octets++) << 16; *)
      let c2 = ( Cs.e_get_char `err buf len
                 |> R.get_ok) (* TODO *)
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
          if 0_l <> logand c4 0x1_00_00_00_l then
          (*            crc ^= CRC24_POLY; *)
            let c5 = logxor c4 0x1_86_4c_fb_l in inner_loop c5 (i+1)
          else
            inner_loop c4 (i+1)
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
  done ;
  Cs.of_cstruct output

type packet_length_type =
  | One_octet
  | Two_octet
  | Four_octet
  (* | Partial_length - TODO: Not clear to me if this is ever used in practice. seems a bit uselesss, and tricky to implement due to the extended state machine required. *)

let pp_packet_length_type fmt t =
  (Fmt.parens Fmt.string) fmt
    (match t with
    | One_octet -> "one octet"
    | Two_octet -> "two octet"
    | Four_octet -> "four octet")

let packet_length_type_enum =
  [ (0 , One_octet)
  ; (1 , Two_octet)
  ; (2 , Four_octet)
(*; (3 , Partial_length)*)
  ]

let packet_length_type_of_size = function
  | s when -1 = Uint32.compare s 192l -> One_octet
  | s when -1 = Uint32.compare s 8384l -> Two_octet
  | _ -> Four_octet

let serialize_packet_length_uint32 (len : Uint32.t) =
  match packet_length_type_of_size len with
  | One_octet -> Cs.make_uint8 (Int32.to_int len)
  (* TODO V3: | Two_octet -> Cs.BE.create_uint16 (Int32.to_int len)*)
  | Two_octet ->
    let len = Int32.to_int len in
    let converted =
      ((len land 0xff00) - 256 + (192*256))
      + ((len land 0xff) + 256 - 192)
      |> Cs.BE.create_uint16
    in
    Logs.debug (fun m -> m "serializing packet length of %d -> %a" len
                   Cs.pp_hex converted) ;
    converted
  | Four_octet -> (*This is a V4 "five octet": *)
    Cs.concat [Cs.make_uint8 0xff ; Cs.BE.create_uint32 len]

let serialize_packet_length_int i =
  (* TODO guard exception *)
  Uint32.of_int i |> serialize_packet_length_uint32

let serialize_packet_length cs =
  Cs.len cs |> serialize_packet_length_int
  (* we don't use Usane.Uint32 above because
     a) we actually want to wrap values larger than 31 bits
     b) Cs.len returning an int is a shortcoming of the API
  *)

let int_of_packet_length_type needle =
  find_enum_value needle packet_length_type_enum |> R.get_ok

let packet_length_type_of_int needle =
  Logs.debug (fun m -> m "packet_length_type_of_int %d" needle) ;
  find_enum_sumtype needle packet_length_type_enum

let v4_packet_length_of_cs (e:'e) (buf : Cs.t)
  : (Usane.Uint16.t * Usane.Uint32.t, 'e) result =
  (* see https://tools.ietf.org/html/rfc4880#section-4.2.2 *)
  Cs.e_get_char e buf 0 >>= fun first_c ->
  let first = int_of_char first_c in
  match first_c with
  | ('\000'..'\191') -> Ok (1 , Uint32.of_int first)
  | ('\192'..'\223') ->
      Cs.get_uint8 buf 1 |> R.reword_error (function _ -> e)
      >>| fun second ->
      (2 , Uint32.of_int @@ ((first - 192) lsl 8) + second + 192)
  | ('\224'..'\254') -> Error (`Msg "Unimplemented feature: partial_length")
  | '\255' ->
      Cs.BE.get_uint32 buf 1 |> R.reword_error (function _ -> e)
      >>| fun length -> (5, length)

let v3_packet_length_of_cs (e:'e) buf = function
  | One_octet ->
      Cs.e_get_uint8 e buf 0 >>| Uint32.of_int >>| fun len -> (1, len)
  | Two_octet ->
      Cs.BE.e_get_uint16 e buf 0 >>| fun length -> (2, Uint32.of_int length)
  | Four_octet ->
      Cs.BE.e_get_uint32 e buf 0 >>| fun length -> (4, (length :> Uint32.t))
  (*| Partial_length -> R.error (`Unimplemented_feature "partial_length") *)

let consume_packet_length length_type buf :
  (Cs.t * Cs.t,
   [>`Incomplete_packet | `Msg of string])
    result =
  (* TODO ? make length_type an optional ?v3_length_type arg *)
  begin match length_type with
    | None -> v4_packet_length_of_cs `Incomplete_packet buf
    | Some length -> v3_packet_length_of_cs `Incomplete_packet buf length
  end >>= fun (start , length) ->
  match Uint32.to_int length with
  | None -> error_msg (fun m -> m "consume_packet_length: Invalid packet length: %ld" length)
  | Some length ->
    Cs.split_result ~start buf length
    |> R.reword_error (function _ ->  `Incomplete_packet)
    >>| fun ((header,_) as pair) ->
    Logs.debug (fun m -> m "consume_packet_length: consuming %a"
                   Cs.pp_hex header) ;
    pair

(* https://tools.ietf.org/html/rfc4880#section-4.2 : Packet Headers *)
type packet_header =
  { length_type : packet_length_type option
  ; packet_tag  : packet_tag_type
  ; new_format  : bool
  }

let char_of_packet_header ph : (char,'error) result =
  begin match ph with
  | { new_format = true ; packet_tag ; length_type = None } ->
      (1 lsl 6) lor (* 1 bit, new_format = true *)
      (int_of_packet_tag_type packet_tag) (* 6 bits*)
      |> R.ok
    | { new_format ; packet_tag ; length_type = Some length_type } when new_format = false ->
      ((int_of_packet_length_type length_type) land 0x3) (* 2 bits *)
      lor (((int_of_packet_tag_type packet_tag) land 0xf) lsl 2) (* 4 bits *)
      |> R.ok
  | { new_format = false ; _ } ->
    error_msg (fun m -> m "TODO V3 packet header serialization not implemented")
  | _ -> error_msg (fun m -> m "Invalid bitfield combination in packet header")
  end
  >>= fun pt ->
  pt lor (1 lsl 7) (* always one, 1 bit *)
  |> Char.chr |> R.ok

let packet_header_of_char (c : char)
  : (packet_header, [> `Msg of string]) result =
  let bit_7_set x = x land (1 lsl 7) <> 0 in
  let bit_6_set x = x land (1 lsl 6) <> 0 in
  let bits_5_through_2 x = (x land (32 lor 16 lor 8 lor 4)) lsr 2 in
  let bits_1_through_0 x = x land (1 lor 2) in
  let bits_5_through_0 x = x land (64-1) in
  let c_int = int_of_char c in
  let new_format = bit_6_set c_int in
  if not (bit_7_set c_int) then
    error_msg (fun m -> m "Not a PGP packet header (MSB not set: %02x)" c_int)
  else
    begin match new_format with
      | true ->
        bits_5_through_0 c_int |> Char.chr
        |> packet_tag_type_of_char >>= fun pt ->
        Logs.debug (fun m -> m "Read a V4 packet header %a" pp_packet_tag pt) ;
        R.ok (pt, None)
      | false ->
        packet_tag_type_of_char (Char.chr (bits_5_through_2 c_int))
        >>= fun packet_tag ->
        let length_type =
          bits_1_through_0 c_int
          |> packet_length_type_of_int
          |> R.get_ok
        in
        R.ok (packet_tag, Some length_type)
    end >>= fun (packet_tag , length_type) ->
  Ok { length_type
     ; packet_tag
     ; new_format
     }

let consume_packet_header buf :
  ((packet_header * Cs.t), [> `Msg of string | `Incomplete_packet]) result =
  Cs.e_split `Incomplete_packet buf 1 >>= fun (header_buf , buf_tl) ->
  Cs.e_get_char `Incomplete_packet header_buf 0
  >>= packet_header_of_char >>| fun pkt_header -> (pkt_header , buf_tl)

let v4_verify_version (buf : Cs.t) :
  (unit, [> `Msg of string | `Incomplete_packet]) result =
  Cs.e_get_char `Incomplete_packet buf 0 >>= fun version ->
  if version <> '\x04' then
    error_msg (fun m -> m "Expected OpenPGP version 4, got v. %d" (Char.code version))
  else
    R.ok ()

let dsa_asf_are_valid_parameters ~(p:Nocrypto.Numeric.Z.t) ~(q:Z.t) ~hash_algo
  : (unit,'error) result =
  (* Ideally this function would reside in Nocrypto.Dsa *)

  let mpi_error = msg_of_invalid_mpi_parameters [p;q] in

  (* From RFC 4880 (we whitelist these parameters): *)
  (*  DSA keys MUST also be a multiple of 64 bits, *)
  (*  and the q size MUST be a multiple of 8 bits. *)
  (*  1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 hash *)
  (*  2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash *)
  (*  2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash *)
  (*  3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash *)
  begin match Z.numbits p , Z.numbits q, hash_algo with
    | 1024 , 160 ,(SHA1|SHA224|SHA256|SHA384|SHA512) -> R.ok ()
    | 2048 , 224 ,(SHA224|SHA256|SHA384|SHA512) -> R.ok ()
    | (2048|3072), 256 ,(SHA256|SHA384|SHA512) -> R.ok ()
    | _ , _ , _ ->  Logs.debug (fun m -> m "failing dsa param checks") ;
                    Error mpi_error
  end >>= fun () ->

  (* - q : q < p *)
  e_true mpi_error (-1 = compare q p) >>= fun () ->

  (* - p,q : must be prime: *)
  mpis_are_prime [p;q] >>= fun () ->

  (* - q : must be (prime) divisor of p-1 : *)
  e_true mpi_error Z.(equal zero (rem (pred p) q))

  (* TODO - g : g = h^(p-1)/q mod p *)
  (* TODO rest of http://csrc.nist.gov/groups/STM/cavp/documents/dss/DSAVS.pdf *)

let two_octet_checksum data =
  (* This is used to compute checksums on private keys.
     See https://tools.ietf.org/html/rfc4880#section-5.5.3
     a two-octet checksum of the plaintext of the algorithm-specific portion
     (sum of all octets, mod 65536).*)
  Cs.to_list data
  |> List.fold_left (fun acc c -> (acc + Char.code c) land 0xffff) 0
  |> Cs.BE.create_uint16
