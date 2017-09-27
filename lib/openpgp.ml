open Rresult
open Types

type packet_type =
  | Signature_type of Signature_packet.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t
  | Secret_key_packet of Public_key_packet.private_key
  | Secret_key_subpacket of Public_key_packet.private_key
  | Trust_packet of Cs.t

let packet_tag_of_packet = begin function
  | Signature_type _ -> Signature_tag
  | Public_key_packet _ -> Public_key_tag
  | Public_key_subpacket _ -> Public_subkey_tag
  | Uid_packet _ -> Uid_tag
  | Secret_key_packet _ -> Secret_key_tag
  | Secret_key_subpacket _ -> Secret_subkey_tag
  | Trust_packet _ -> Trust_packet_tag
  end

let encode_ascii_armor (armor_type:ascii_packet_type) (buf : Cstruct.t) =
  let newline = Cs.of_string "\r\n" in
  let rec base64_encoded acc buf_tl =
    (* 54 / 3 * 4 = 72; output chunks of 72 chars.
     * The last line will not be newline-terminated. *)
    let (chunk,next_tl) = Cstruct.split buf_tl (min (Cs.len buf_tl) 54) in
    if Cs.len chunk <> 0 then
      base64_encoded ((Nocrypto.Base64.encode chunk) :: acc) next_tl
    else
      match acc with
      | [] -> Cs.create 0 (* if input was empty, return empty output *)
      | acc_hd::acc_tl ->
      let end_lines = List.map (fun line -> Cs.concat [line;newline]) acc_tl in
      Cs.concat @@ List.rev (acc_hd::end_lines)
  in
  let cs_armor_magic = string_of_ascii_packet_type armor_type |> Cs.of_string in
    Cs.concat
    [ Cs.of_string "-----BEGIN PGP " ; cs_armor_magic ; Cs.of_string "-----\r\n"
      (*; TODO headers*)
    ; newline (* <-- end of headers*)

    ; base64_encoded [] buf
    ; newline

    (* CRC24 checksum: *)
    ; Cs.of_string "="; Nocrypto.Base64.encode (crc24 buf) ; newline

    (* END / footer: *)
    ; Cs.of_string "-----END PGP " ; cs_armor_magic ; Cs.of_string "-----\r\n"
    ]

let decode_ascii_armor (buf : Cstruct.t) =
  (* see https://tools.ietf.org/html/rfc4880#section-6.2 *)
  let max_length = 73 in (*maximum line length *)

  begin match Cs.next_line ~max_length buf with
    | `Next_tuple pair -> Ok pair
    | `Last_line _ ->
      error_msg
        (fun m -> m "Unexpected end of ascii armor; expected more lines (%d)"
                                                                (Cs.len buf))
  end >>= fun (begin_header, buf) ->

  Logs.debug (fun m -> m "Checking that armor begins with -----BEGIN PGP...") ;
  Cs.e_split (`Msg "`Invalid") begin_header (String.length "-----BEGIN PGP ")
  >>= fun (begin_pgp, begin_tl) ->
  Cs.e_equal_string (`Msg "Invalid") "-----BEGIN PGP " begin_pgp >>= fun () ->

  Logs.debug (fun m -> m "Checking that armor line ends with five dashes") ;
  Cs.e_split (`Msg "first line doesn't end in dashes")
    begin_tl (Cs.len begin_tl -5) >>= fun (begin_type , begin_tl) ->
  Cs.e_equal_string (`Msg "Invalid") "-----" begin_tl >>= fun () ->

  (* check that we know how to handle this type of ascii-armored message: *)
  Logs.debug (fun m -> m "Checking that we know how to handle this type of armored message") ;
  begin match Cs.to_string begin_type with
      | "PUBLIC KEY BLOCK" -> Ok Ascii_public_key_block
      | "SIGNATURE" -> Ok Ascii_signature
      | "MESSAGE" -> Ok Ascii_message
      | "PRIVATE KEY BLOCK" -> Ok Ascii_private_key_block
      | unknown -> error_msg (fun m -> m "Unknown armor type: %S" unknown)
  end
  >>= fun pkt_type ->

  Logs.debug (fun m -> m "Skipping armor headers (like \"Version:\"; not handled in this implementation)") ;
  let rec skip_headers buf_tl =
    match Cs.next_line ~max_length buf_tl  with
    | `Last_line not_body_cs ->
      error_msg (fun m -> m "Missing armored body, expected here: %a"
                    Cstruct.hexdump_pp not_body_cs)
    | `Next_tuple (header, buf_tl) ->
      if Cs.len header = 0 then
        R.ok buf_tl
      else
        log_msg (fun m -> m "Skipping header: %S" (Cs.to_string header))
          buf_tl |> skip_headers
  in
  skip_headers buf
  >>= fun body ->

  let rec decode_body acc tl : (Cs.t*Cs.t,[> `Msg of string]) result =
    let b64_decode cs =
      Nocrypto.Base64.decode cs
      |> R.of_option ~none:(fun()->
          error_msg (fun m -> m "Cannot base64-decode body line: %a"
                        Cstruct.hexdump_pp cs ))
    in
    begin match Cs.next_line ~max_length:76 tl with
      | `Last_line not_end_cs ->
        error_msg (fun m -> m "Unexpected end of armored body: %a"
                  Cstruct.hexdump_pp not_end_cs)
      | `Next_tuple (cs,tl) when Some 0 = Cs.index_opt cs '=' ->
        Cs.e_split ~start:1 (`Msg "CRC24 must start with '='-sign") cs 4
        >>= fun (b64,must_be_empty) ->
        Cs.e_is_empty (`Msg "CRC-24 is not 24 bits") must_be_empty >>= fun () ->
        b64_decode b64 >>= fun target_crc ->
        Logs.debug (fun m -> m "target crc: %s" (Cs.to_hex target_crc));
        let decoded = List.rev acc |> Cs.concat in
        let decoded_crc24 = crc24 decoded in
        if Cs.equal target_crc decoded_crc24 then
          Ok (decoded, tl)
        else
          error_msg (fun m -> m "CRC-24 mismatch! Expected %a, got %a"
                 Cstruct.hexdump_pp target_crc Cstruct.hexdump_pp decoded_crc24)
      | `Next_tuple (cs,tl) ->
        b64_decode cs >>= fun decoded ->
        decode_body (decoded::acc) tl
    end
  in
  log_msg (fun m -> m "Decoding armored body")
  @@ decode_body [] body >>= fun (decoded, buf) ->

  log_msg (fun m -> m "Now we should be at the last line.") @@
  begin match Cs.next_line ~max_length buf with
    | `Next_tuple ok -> Ok ok
    | `Last_line cs -> Ok (cs, Cs.create 0)
  end
  >>= fun (end_line, buf) ->

  Logs.debug (fun m -> m "Checking that there is no data after the footer") ;
  let rec loop buf =
    match Cs.next_line ~max_length buf with
    | `Next_tuple (this,tl) ->
      Cs.e_is_empty (`Msg "packet contains data after footer") this >>= fun () ->
      loop tl
    | `Last_line this -> Cs.e_is_empty (`Msg "last armor line is not empty") this
  in loop buf >>= fun () ->

  Logs.debug (fun m -> m "Checking that last armor contains correct END footer") ;
  end_line |> Cs.e_equal_string (`Msg "Armored message is missing end block")
  (begin match pkt_type with
  | Ascii_public_key_block -> "-----END PGP PUBLIC KEY BLOCK-----"
  | Ascii_signature -> "-----END PGP SIGNATURE-----"
  | Ascii_private_key_block -> "-----END PGP PRIVATE KEY BLOCK-----"
  | Ascii_message_part_x _ (* TODO need to verify that this is correct *)
  | Ascii_message_part_x_of_y _
  | Ascii_message -> "-----END PGP MESSAGE-----"
  end) >>= fun () ->
  Ok (pkt_type, decoded)

let parse_packet_body packet_tag pkt_body
  : (packet_type, [> `Msg of string | `Incomplete_packet ]) result =
  begin match packet_tag with
    | Public_key_tag ->
      Public_key_packet.parse_packet pkt_body
      >>| fun pkt -> Public_key_packet pkt
    | Public_subkey_tag ->
      Public_key_packet.parse_packet pkt_body
      >>| fun pkt -> Public_key_subpacket pkt
    | Uid_tag ->
      Uid_packet.parse_packet pkt_body
      >>| fun pkt -> Uid_packet pkt
    | Signature_tag ->
      Signature_packet.parse_packet pkt_body
      >>| fun pkt -> Signature_type pkt
    | Secret_key_tag -> Public_key_packet.parse_secret_packet pkt_body
                        >>| fun pkt -> Secret_key_packet pkt
    | Secret_subkey_tag -> Public_key_packet.parse_secret_packet pkt_body
                           >>| fun pkt -> Secret_key_subpacket pkt
    | Trust_packet_tag -> Ok (Trust_packet pkt_body)
    | User_attribute_tag ->
        error_msg
          (fun m -> m "parse_packet_body: Unimplemented: User_attribute_tag")
  end

let pp_packet ppf = begin function
  | Public_key_packet pkt ->
      Fmt.pf ppf "Public key: @[<v>%a@]" Public_key_packet.pp pkt
  | Public_key_subpacket pkt ->
      Fmt.pf ppf "Public subkey: @[<v>%a@]" Public_key_packet.pp pkt
  | Secret_key_packet pkt ->
      Fmt.pf ppf "Secret key: @[<v>%a@]" Public_key_packet.pp_secret pkt
  | Secret_key_subpacket pkt ->
      Fmt.pf ppf "Secret subkey: @[<v>%a@]" Public_key_packet.pp_secret pkt
  | Uid_packet pkt ->
      Fmt.pf ppf "UID: @[<v>%a@]" Uid_packet.pp pkt
  | Signature_type pkt ->
      Fmt.pf ppf "Signature: @[<v>%a@]" Signature_packet.pp pkt
  | Trust_packet cs ->
      Fmt.pf ppf "Trust packet (ignored): @[%a@]" Cstruct.hexdump_pp cs
  end

let hash_packet version hash_cb = begin function
  | Uid_packet pkt -> Ok (Uid_packet.hash pkt hash_cb version)
  | Public_key_subpacket pkt
  | Public_key_packet pkt -> Ok (Public_key_packet.hash_public_key pkt hash_cb)
  | Secret_key_subpacket pkt
  | Secret_key_packet pkt ->
      Ok (Public_key_packet.(hash_public_key pkt.public hash_cb))
  | Signature_type pkt -> Signature_packet.hash pkt hash_cb
  | Trust_packet _ ->
      error_msg (fun m -> m "Should NOT be hashing Trust_packets!")
  end

let serialize_packet version (pkt:packet_type) =
  begin match pkt with
    | Uid_packet pkt -> Uid_packet.serialize pkt
    | Signature_type pkt -> Signature_packet.serialize pkt
    | Public_key_packet pkt
    | Public_key_subpacket pkt -> Public_key_packet.serialize version pkt
    | Trust_packet cs -> Ok cs
    | Secret_key_packet pkt -> Public_key_packet.serialize_secret version pkt
    | Secret_key_subpacket pkt -> Public_key_packet.serialize_secret version pkt
  end >>= fun body_cs ->

  begin match version with
  | V3 ->
    let length_type = packet_length_type_of_size
        (Cs.len body_cs |> Int32.of_int) in
    error_msg (fun m -> m "serialize_packet: V3: try serialize length type: %a"
                 pp_packet_length_type length_type)
  | V4 ->
    char_of_packet_header {new_format = true; length_type = None
                          ; packet_tag = packet_tag_of_packet pkt}
    >>| Cs.of_char
    >>| fun packet_header -> Cs.concat [ packet_header
                                       ; serialize_packet_length body_cs ]
  end >>| fun header_cs ->
  Logs.debug (fun m -> m "serialized packet @[<v>%a@ header: %a@ contents: %a@]"
               pp_packet pkt
               Cstruct.hexdump_pp header_cs
               Cstruct.hexdump_pp body_cs );
  Cs.concat [header_cs ; body_cs ]

let next_packet (full_buf : Cs.t) :
  ((packet_tag_type * Cs.t * Cs.t) option
   , [> `Msg of string | `Incomplete_packet]) result =
  if Cs.len full_buf = 0 then Ok None else
  consume_packet_header full_buf
  >>= begin function
  | { length_type ; packet_tag; _ } , pkt_header_tl ->
    consume_packet_length length_type pkt_header_tl
    >>| fun (pkt_body, next_packet) ->
    Some (packet_tag , pkt_body, next_packet)
  end

let parse_packets cs : (('ok * Cs.t) list, 'error) result =
  (* TODO: 11.1.  Transferable Public Keys *)
  let rec loop acc cs_tl =
    next_packet cs_tl
    >>= begin function
      | Some (packet_type , pkt_body, next_tl) ->
        Logs.debug (fun m -> m "Will read a %a packet"
                       pp_packet_tag packet_type) ;
        parse_packet_body packet_type pkt_body >>= fun parsed ->
        Logs.debug (fun m -> m "%a" pp_packet parsed) ;
        loop ((parsed,pkt_body)::acc) next_tl
      | None ->
        R.ok (List.rev acc)
    end
  in
  loop [] cs

module Signature =
struct
  include Signature_packet

  type uid =
    { uid : Uid_packet.t
    ; certifications : Signature_packet.t list
    }

  type user_attribute =
    { certifications : Signature_packet.t list
      (* : User_attribute_packet.t *)
    }

  type subkey =
    { key : Public_key_packet.t
    ; binding_signatures : Signature_packet.t list
    (* plus optionally revocation signatures: *)
    ; revocations : Signature_packet.t list
    }

  type private_subkey = { secret_key : Public_key_packet.private_key
                        ; binding_signatures : Signature_packet.t list
                        ; revocations : Signature_packet.t list }

  let public_subkey_of_private {secret_key;binding_signatures;revocations} =
    { key = secret_key.Public_key_packet.public
    ; binding_signatures; revocations }

  type transferable_public_key =
    { (* V4 public key. V3 is slightly different (see RFC 4880: 12.1)*)
    (* One Public-Key packet *)
      root_key : Public_key_packet.t
      (* Zero or more revocation signatures *)
      ; revocations : Signature_packet.t list
    (* One or more User ID packets *)
    ; uids : uid list
    (* Zero or more User Attribute packets *)
    ; user_attributes : user_attribute list
    (* Zero or more subkey packets *)
    ; subkeys : subkey list
    }

  type transferable_secret_key =
    { root_key : Public_key_packet.private_key
    ; uids : uid list
    ; secret_subkeys : private_subkey list
    }

  let transferable_public_key_of_transferable_secret_key
      (sk:transferable_secret_key) =
    { root_key = Public_key_packet.public_of_private sk.root_key
    ; revocations = [] (*TODO*)
    ; uids = sk.uids
    ; user_attributes = [] (*TODO*)
    ; subkeys = sk.secret_subkeys |> List.map public_subkey_of_private
    }

  let check_signature_transferable current_time (pk:transferable_public_key)
                                   hash_final signature  =
    let pks = pk.root_key :: (pk.subkeys |> List.map (fun k -> k.key)) in
    (* ^-- TODO filter out non-signing-keys*)
    check_signature current_time pks hash_final signature

  let verify_detached_cb ~current_time (pk:transferable_public_key)
      (signature:t) (cb:(unit -> (Cs.t option, [> `Msg of string]) result))
  : ('ok, [> `Msg of string]) result =
    (* TODO check pk is valid *)
    true_or_error (signature.signature_type = Signature_of_binary_document)
      (fun m -> m "TODO not implemented: we do not handle the newline-normalized@,(->\\r\\n) signature_type.Signature_of_canonical_text_document") >>= fun () ->
    let (hash_cb, hash_final) = digest_callback signature.hash_algorithm in
    Logs.debug (fun m -> m "hashing detached signature with callback...");
    let rec hash_loop () =
      cb () >>= function
      | None -> Ok signature
      | Some data -> hash_cb data ; hash_loop ()
    in hash_loop ()
    >>= fun _ -> hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->
    Logs.debug (fun m -> m "Checking detached signature");
    check_signature_transferable current_time pk hash_final signature

  let verify_detached_cs ~current_time pk signature cs =
    let (hash_cb, hash_final) = digest_callback signature.hash_algorithm in
    true_or_error (signature.signature_type = Signature_of_binary_document)
      (fun m -> m "TODO not implemented: we do not handle the newline-normalized@,(->\\r\\n) signature_type.Signature_of_canonical_text_document") >>= fun () ->
    Logs.debug (fun m -> m "hashing detached signature with Cs.t ...");
    hash_cb cs ;
    hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->
    Logs.debug (fun m -> m "Checking detached signature");
    check_signature_transferable current_time pk hash_final signature

  let check_signature_on_root_and_subkey ~current_time sig_types
                                          root_pk subkey t =
    true_or_error (List.exists (fun st -> st = t.signature_type) sig_types)
      (fun m -> m "Invalid signature type %a rejected, expecting one of @[%a@]"
          pp_signature_type t.signature_type
          Fmt.(list pp_signature_type) sig_types
      )
    >>= fun () ->

    (* set up hashing with this signature: *)
    let (hash_cb, hash_final) = digest_callback t.hash_algorithm in

    (* This signature is calculated directly on the
       primary key and subkey, and not on any User ID or other packets.*)
    hash_packet V4 hash_cb (Public_key_packet root_pk) >>= fun () ->
    hash_packet V4 hash_cb (Public_key_packet subkey.key) >>= fun () ->
    hash_packet V4 hash_cb (Signature_type t) >>= fun () ->
    let designated_keys =
      match t.signature_type with
      | Primary_key_binding_signature -> [subkey.key]
      | _ -> [root_pk]
    in
    check_signature current_time designated_keys hash_final t
    |> log_failed (fun m -> m "Rejecting bad signature on (root & subkey)")
    >>| log_msg (fun m -> m "Accepting signature on (root & subkey)")

  let check_embedded_signature current_time pk t subkey =
    (* RFC 4880: 0x19: Primary Key Binding Signature
       This signature is a statement by a signing subkey, indicating
       that it is owned by the primary key and subkey.  This signature
       is calculated the same way as a 0x18 signature: directly on the
        primary key and subkey, and not on any User ID or other packets. *)
    check_signature_on_root_and_subkey ~current_time
      [Primary_key_binding_signature] pk subkey t
    |> log_failed (fun m -> m "Rejecting invalid embedded signature")
    >>| log_msg (fun m -> m "Accepting embedded signature")

  let check_subkey_binding_signature ~current_time root_pk subkey t =
     public_key_not_expired current_time subkey t >>= fun () ->

     (* RFC 4880: 0x18: Subkey Binding Signature
        This signature is a statement by the top-level signing key that
         indicates that it owns the subkey.*)

     (* A signature that binds a signing subkey MUST have
        an Embedded Signature subpacket in this binding signature that
        contains a 0x19 signature made by the signing subkey on the
        primary key and subkey: *)
    begin match subkey.Public_key_packet.algorithm_specific_data with
    | Public_key_packet.RSA_pubkey_encrypt_asf _
    | Public_key_packet.Elgamal_pubkey_asf _ -> Ok ()
    | Public_key_packet.RSA_pubkey_sign_asf _
    | Public_key_packet.RSA_pubkey_encrypt_or_sign_asf _
    | Public_key_packet.DSA_pubkey_asf _ ->
        (* 5.2.3.21.  Key Flags
           The flags in this packet may appear in self-signatures or in
           certification signatures.  They mean different things depending on
           who is making the statement -- for example, a certification
           signature that has the "sign data" flag is stating that the
           certification is for that use. *)
        if SubpacketMap.get_opt Key_usage_flags t.subpacket_data |> (function
           | Some (Key_usage_flags { certify_keys = false; _ })  -> true
           | _ -> false (* fail if certify_keys = false or if there are no KUF*)
        ) then begin
          Logs.debug (fun m -> m "Accepting subkey binding without %s @[<v>%s@]"
                                 "embedded signature because the key flags have"
                                " { certify_keys = false }");
          R.ok ()
        end else
           (* Subkeys that can be used for signing must accept inclusion by
              embedding a signature on the root key (made using the subkey)*)
           SubpacketMap.get Embedded_signature t.subpacket_data
           |> log_failed (fun m ->
               m "no embedded signature subpacket in subkey binding signature")
           >>= fun (Embedded_signature embedded_sig) ->
           check_embedded_signature current_time root_pk
             embedded_sig { key = subkey
                          ; revocations = []; binding_signatures=[]}
           >>= fun `Good_signature -> R.ok ()
      end

  let sign ~(g : Nocrypto.Rng.g) ~(current_time : Ptime.t) signature_type
      (sk : Public_key_packet.private_key)
      (signature_subpackets : signature_subpacket SubpacketMap.t)
      hash_algorithm (hash_cb,digest_finalizer) (* TODO def cb type with algo *)
    =
    let pk = Public_key_packet.public_of_private sk in
    (* TODO validate subpackets *)
    let public_key_algorithm =
      (Public_key_packet.public_key_algorithm_of_asf
         pk.Public_key_packet.algorithm_specific_data) (* TODO *)
    in
    (* add Signature_creation_time with [current_time] if no creation time: *)
    let signature_subpackets :signature_subpacket SubpacketMap.t =
      let v4_fp = pk.Public_key_packet.v4_fingerprint in
      SubpacketMap.upsert Issuer_fingerprint (Issuer_fingerprint (V4,v4_fp))
        signature_subpackets
      |> SubpacketMap.upsert Issuer_keyid
        (Issuer_keyid (Cs.sub_unsafe v4_fp 12 8))
      |> SubpacketMap.add_if_empty Signature_creation_time
        (Signature_creation_time current_time)
    in
    Logs.debug (fun m -> m "sign: constructing signature tbh") ;
    Signature_packet.construct_to_be_hashed_cs_manual V4
      signature_type public_key_algorithm
      hash_algorithm (SubpacketMap.to_list signature_subpackets)
    >>| hash_cb >>= fun () ->
    Logs.debug (fun m -> m "sign: computing digest") ;

    let digest = digest_finalizer () in
    Logs.debug (fun m -> m "sign: got digest %s" (Cs.to_hex digest)) ;
    begin match sk.Public_key_packet.priv_asf with
    | Public_key_packet.DSA_privkey_asf key ->
      let (r,s) = Nocrypto.Dsa.sign ~mask:(`Yes_with g) ~key digest in
      Ok (DSA_sig_asf {r = Types.mpi_of_cs_no_header r
                      ; s = mpi_of_cs_no_header s})
    | Public_key_packet.RSA_privkey_asf key ->
      Logs.debug (fun m -> m "sign: signing digest with RSA key") ;
      let module PKCS : Nocrypto.Rsa.PKCS1.S =
        (val (nocrypto_pkcs_module_of_hash_algorithm hash_algorithm)) in
      Ok (RSA_sig_asf { m_pow_d_mod_n =
                          PKCS.sign_cs ~mask:(`Yes_with g) ~key ~digest
                          |> mpi_of_cs_no_header
                      })
    | Public_key_packet.Elgamal_privkey_asf _ ->
      error_msg (fun m -> m "Cannot sign with El-Gamal key")
    end
    >>| fun algorithm_specific_data ->
       { signature_type ; public_key_algorithm ; hash_algorithm
       ; algorithm_specific_data ; subpacket_data = signature_subpackets}

  let sign_detached_cb ~g ~current_time sk hash_algo ((hash_cb, _) as hash_tuple) io_cb =
    let rec io_loop () =
      io_cb () >>= function
      | None -> Ok ()
      | Some data -> hash_cb data ; io_loop ()
    in
    io_loop () >>= fun () ->
    let subpackets = SubpacketMap.empty in
    sign ~g ~current_time Signature_of_binary_document sk subpackets hash_algo hash_tuple

  let sign_detached_cs ~g ~current_time secret_key hash_algo target_cs =
    let subpackets = SubpacketMap.empty (* TODO support expiry time *) in
    let (hash_cb, _) as hash_tuple = digest_callback hash_algo in
    hash_cb target_cs ;
    sign ~g ~current_time
      Signature_of_binary_document
      secret_key subpackets
      hash_algo hash_tuple

  let certify_uid
      ~(g : Nocrypto.Rng.g)
      ~(current_time : Ptime.t)
      (priv_key : Public_key_packet.private_key) uid
    : (Signature_packet.t, [>]) result =
    (* TODO handle V3 *)
    (* TODO pick hash from priv_key.Preferred_hash_algorithms if present: *)
    let hash_algo = SHA384 in
    let subpackets : signature_subpacket SubpacketMap.t =
      SubpacketMap.empty |>
      SubpacketMap.upsert Key_usage_flags
        (Key_usage_flags { certify_keys = true ; unimplemented = '\000'
                        ; sign_data = true ; encrypt_communications = false
                        ; encrypt_storage = false ; authentication = false })
      |> SubpacketMap.upsert Key_expiration_time
        (Key_expiration_time (Ptime.Span.of_int_s @@ 86400*365))
    in
    let (hash_cb, _) as hash_tuple = digest_callback hash_algo in
    Logs.debug (fun m -> m "certify_uid: hashing public key packet") ;
    hash_packet V4 hash_cb (Public_key_packet
      (Public_key_packet.public_of_private priv_key)) >>= fun () ->
    Logs.debug (fun m -> m "certify_uid: hashing UID packet") ;
    hash_packet V4 hash_cb (Uid_packet uid) >>= fun () ->
    Logs.debug (fun m -> m "certify_uid: producing signature") ;
    sign ~g ~current_time
      Positive_certification_of_user_id_and_public_key_packet
      priv_key subpackets
      hash_algo hash_tuple

  let certify_subkey ~g ~current_time
                     (priv_key:Public_key_packet.private_key) subkey
    : (Signature_packet.t, [>]) result =
    (* TODO handle V3 *)
    (* TODO pick hash from priv_key.Preferred_hash_algorithms if present: *)
    let hash_algo = SHA384 in
    let subpackets = SubpacketMap.empty in
    let (hash_cb, _) as hash_tuple = digest_callback hash_algo in
    hash_packet V4 hash_cb (Public_key_packet
       (Public_key_packet.public_of_private priv_key)) >>= fun () ->
    (* TODO add Embedded_signature if the key can be used for signing
            or certifying other keys *)
    hash_packet V4 hash_cb (Public_key_packet
      (Public_key_packet.public_of_private subkey)) >>= fun () ->
    sign ~g ~current_time
      Subkey_binding_signature
      priv_key subpackets
      hash_algo hash_tuple

  let filter_signature_types sig_types sigs =
    List.filter (fun t -> List.mem t.signature_type sig_types) sigs

  let take_signatures_of_types sig_types (packets:'datatype) =
      packets |> list_take_leading
        (function
          | (Signature_type signature, _) ->
            e_true (`Msg "wrong sig type in packet")
              (filter_signature_types sig_types [signature] <> [])
               >>| fun () -> signature
          | _ -> Error (`Msg "no signature in packet list")
        )

  let validate_uid_certification ~current_time (root_pk:Public_key_packet.t)
      (uid:packet_type) signature =
    (* set up hashing with this signature: *)
    let (hash_cb, hash_final) = digest_callback signature.hash_algorithm in
    (* TODO handle version V3 *)
    hash_packet V4 hash_cb (Public_key_packet root_pk) >>= fun () ->
    hash_packet V4 hash_cb uid >>= fun () ->
    hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->

    (* Check that the root key has not expired with this UID *)
    public_key_not_expired current_time root_pk signature >>= fun () ->

    check_signature current_time [root_pk] hash_final signature
    |> log_failed (fun m -> m "signature check failed on a uid sig")

  let take_and_validate_certifications packet_tag
      (validation_cb : packet_type -> Signature_packet.t -> ('ok,'error) result)
      sig_types packets =
    let pair_must_be tag ((t,_) as ret) =
      e_true (`Msg "not tag") (tag = packet_tag_of_packet t) >>| fun () -> ret
    in

    (* TODO make validation callback take a list of valid signing PKs*)
    let rec inner_loop
        (acc : (packet_type * Signature_packet.t list) list) packets =
      let (objects, (packets:(packet_type*Cs.t)list)) =
        list_take_leading (pair_must_be packet_tag) packets |> R.get_ok in
      if objects = [] then
        (* Return from loop: *)
        Ok (List.rev acc , packets)
      else
        list_drop_e_n (`Msg "while dropping unsigned objects")
          ((List.length objects)-1) objects
        >>= (function [tuple] -> Ok tuple
                    | lst -> error_msg (fun m -> m "TODOclarify obj err msg: %d"
                                           (List.length lst)))
      >>= fun (obj, _) ->
      packets |> take_signatures_of_types sig_types
      >>= fun (certifications, packets) ->
      (* The certifications can be made by anyone, we are only concerned with the ones made by the root_pk *)
      let valid_certifications =
        certifications |> List.filter
        (fun certification ->
         match validation_cb obj certification with
         | Ok `Good_signature -> true
         | _ -> false
        )
      in
      if valid_certifications = [] then begin
        error_msg (fun m -> m "Skipping %a due to lack of valid certifications"
                      pp_packet obj )
      end else
         inner_loop ((obj, valid_certifications)::acc) packets
      in inner_loop [] packets

  let transferable_of_packets ~current_time
    (packets : ((packet_type * Cs.t) list) as 'packets)
    (take_root_key_cb : 'packets ->((Public_key_packet.t * 'root_key * 'packets)
                                    ,'error) result)
    (take_subkeys_cb  : Public_key_packet.t -> (* root pk *)
                        'packets ->
                        (('subkey list * 'packets), 'error) result)
    (finalize_key     : 'packets -> 'root_key -> uid list -> 'subkey list ->
        (('transferable_key *'packets), 'error) result)
  : ('transferable_key * 'packets,
     [>  `Incomplete_packet | `Msg of string ] as 'error) result
  =
  let debug_if_any s = begin function
      | [] -> () | lst -> Logs.debug (fun m -> m ("%s: %d") s (List.length lst))
  end in

  take_root_key_cb packets >>= fun (root_pk, root_key, packets) ->
    (* TODO extract version from the root_pk and make sure the remaining packets use the same version *)

  (* RFC 4880: Zero or more revocation signatures: *)
  take_signatures_of_types [Key_revocation_signature] packets
  >>= fun (revocation_signatures , packets) ->

  (* revocation keys are detailed here:
     https://tools.ietf.org/html/rfc4880#section-5.2.3.15 *)
  (* TODO check revocation signatures *)
    (* RFC 4880: - One or more User ID packets: *)
    (* Immediately following each User ID packet, there are zero or more
   Signature packets.  Each Signature packet is calculated on the
   immediately preceding User ID packet and the initial Public-Key
    packet.*)
    (* TODo (followed by zero or more signature packets) -- we fail if there are unsigned Uids - design feature? *)
  (* TODO verify that primary key has key flags "certify" ? *)
    packets |> take_and_validate_certifications Uid_tag
        (validate_uid_certification ~current_time root_pk)
        (* We treat these four completely equally: *)
        [ Generic_certification_of_user_id_and_public_key_packet
        ; Persona_certification_of_user_id_and_public_key_packet
        ; Casual_certification_of_user_id_and_public_key_packet
        ; Positive_certification_of_user_id_and_public_key_packet]
    >>= fun (verified_uids , packets) ->
    true_or_error (verified_uids <> [])
        (fun m -> m "Unable to find at least one verifiable UID.")
    >>= fun () ->
    let verified_uids =
      verified_uids |> List.map
        (fun (Uid_packet uid,certifications) -> {uid;certifications})
    in

    (* Validate user attributes (basically, embedded image files) *)
    let validate_user_attribute_signature _ _ _ (* root_pk obj signature*) =
      error_msg (fun m -> m "validation of user attribute sig not implemented")
    in
    packets |> take_and_validate_certifications User_attribute_tag
      (validate_user_attribute_signature root_pk) []
    >>= fun (verified_user_attributes, packets) ->

    Logs.debug (fun m -> m "About to look for subkeys") ;

    take_subkeys_cb root_pk packets >>= fun (subkey_list, packets) ->
    true_or_error (List.length subkey_list < 500)
      (fun m -> m "Encountered more than 500 subkeys; this is probably not a legitimate public key") >>= fun () ->
    debug_if_any "subkeys" subkey_list ;
    (* TODO consider putting this stuff above, and implementing a counter for DoS prevention *)

    (* transform this stuff into either a private or public key*)
    finalize_key packets root_key verified_uids subkey_list

  let root_sk_of_packets ~current_time packets
    : (transferable_secret_key * 'datatype
      , [> `Msg of string | `Incomplete_packet]) result =
    let take_root_key = function
      | (Secret_key_packet sk, _)::tl ->Ok (sk.Public_key_packet.public, sk, tl)
      | _ -> R.error (`Msg "Transferable secret  key does not start with an SK")
    in
    let take_subkeys root_pk packets =
    (* TODO this is a bit of copy-pasted from root_pk_of_packets; should find a
            way to merge the two *)
      let check_subkey_and_sigs
          ({binding_signatures; revocations; secret_key} as subkey) =
        binding_signatures |> result_filter
          (fun t -> check_subkey_binding_signature ~current_time root_pk
                      secret_key.Public_key_packet.public t
            |> log_failed (fun m -> m "Skipping subkey binding due to sigfail")
          ) >>= fun binding_signatures ->
        true_or_error (binding_signatures <> [])
          (fun m -> m "No valid binding signatures on this subkey")
        >>| fun () ->
        (* TODO handle revocations *)
        {subkey with binding_signatures
                   ; revocations = []}
      in
      let rec find_subkeys_and_their_sigs acc =
        begin function
        | (Secret_key_subpacket subkey, _)::tl ->
          Logs.debug (fun m -> m "got a secret subkey") ;
          tl |> take_signatures_of_types
            [ Subkey_binding_signature ; Subkey_revocation_signature ]
          >>= fun (sigs, non_sig_tl) ->
          let binding_signatures, revocations =
            sigs |> List.partition
              (fun t -> t.signature_type = Subkey_binding_signature) in
          let subkey : private_subkey =
            { secret_key = subkey ; binding_signatures ; revocations }
          in
          begin match check_subkey_and_sigs subkey with
          | Ok subkey -> find_subkeys_and_their_sigs (subkey::acc) non_sig_tl
          | Error _   -> find_subkeys_and_their_sigs acc non_sig_tl (*skip bad*)
          end
        | tl -> Ok (List.rev acc, tl)
        end
      in
      find_subkeys_and_their_sigs [] packets
    in

    let finalize_key packets root_key uids secret_subkeys =
      ( {root_key ; uids; secret_subkeys}
      , packets) |> R.ok
    in
    transferable_of_packets ~current_time packets
      take_root_key
      take_subkeys
      finalize_key

  let root_pk_of_packets (* TODO aka root_key_of_packets *)
    ~current_time
    (packets : ((packet_type * Cs.t) list) as 'packets)
  : (transferable_public_key * 'packets,
     [>  `Incomplete_packet | `Msg of string ] as 'error) result
    =
  (* RFC 4880: 11.1 Transferable Public Keys *)
  (* this function imports the output of gpg --export *)

  (* RFC 4880: - One Public-Key packet: *)
    let take_root_key = begin function
      | (Public_key_packet pk, _) :: tl -> Ok (pk, pk, tl)
      | _ -> R.error (`Msg "Transferable public key does not start with a PK")
    end in

    let take_subkeys root_pk packets =
      let check_subkey_and_sigs
          ({binding_signatures; revocations; key} as subkey) =
        binding_signatures |> result_filter
          (fun t -> check_subkey_binding_signature ~current_time root_pk key t
                    |> log_failed (fun m -> m "Skipping subkey binding due to sigfail")
          ) >>= fun binding_signatures ->
        true_or_error (binding_signatures <> [])
          (fun m -> m "No valid binding signatures on this subkey")
        >>| fun () ->
        (* TODO handle revocations *)
        {subkey with binding_signatures
                   ; revocations = []}
      in
      let rec find_subkeys_and_their_sigs acc =
      begin function
        | (Public_key_subpacket subkey, _)::tl ->
          Logs.debug (fun m -> m "got a public subkey") ;
          tl |> take_signatures_of_types
            [ Subkey_binding_signature ; Subkey_revocation_signature ]
          >>= fun (sigs, non_sig_tl) ->
          let binding_signatures, revocations =
            sigs |> List.partition
              (fun t -> t.signature_type = Subkey_binding_signature) in
          let subkey : subkey =
            { key = subkey ; binding_signatures ; revocations }
          in
          begin match check_subkey_and_sigs subkey with
          | Ok subkey -> find_subkeys_and_their_sigs (subkey::acc) non_sig_tl
          | Error _   -> find_subkeys_and_their_sigs acc non_sig_tl (*skip bad*)
          end
        | tl -> Ok (List.rev acc, tl)
      end
      in
      find_subkeys_and_their_sigs [] packets
    in

    let finalize_key packets root_pk verified_uids verified_subkeys =
    Ok ( { root_key = root_pk
      ; revocations = [] (* TODO *)
      ; uids = verified_uids
      ; user_attributes = [] (* TODO *)
      ; subkeys = verified_subkeys
      }
      , packets)
    in
    transferable_of_packets ~current_time packets
      take_root_key
      take_subkeys
      finalize_key
end

let armored_or_not ?armored armor_type cs =
  match armored with
  | Some false -> Ok cs
  | _ ->
  let decoded = decode_ascii_armor cs in
  begin match armored, decoded with
  | (Some true | None), Ok (my_armor, cs) when my_armor = armor_type -> Ok cs
  | None , Error _->
    Logs.err(fun m -> m "Failed decoding ASCII armor %a, parsing as raw instead"
                pp_ascii_packet_type armor_type ) ; Ok cs
  | _ , _ -> error_msg
      (fun m -> m "Cannot decode OpenPGP ASCII armor of supposed type %a"
          pp_ascii_packet_type armor_type)
  end

let decode_public_key_block ~current_time ?armored cs
  : (Signature.transferable_public_key * (packet_type * Cs.t) list
    , [> `Msg of string]) result =
  armored_or_not ?armored Ascii_public_key_block cs
  >>= (fun pub_cs -> parse_packets pub_cs |> R.reword_error Types.msg_of_error)
  >>= (fun pub_cs ->
  Signature.root_pk_of_packets ~current_time pub_cs
  |> R.reword_error Types.msg_of_error)

let decode_secret_key_block ~current_time ?armored cs =
  armored_or_not ?armored Ascii_private_key_block cs
  >>= (fun sec_cs -> parse_packets sec_cs)
  >>= (fun sec_cs -> Signature.root_sk_of_packets ~current_time sec_cs )

let decode_detached_signature ?armored cs =
  armored_or_not ?armored Ascii_signature cs
  >>= (fun sig_cs -> parse_packets sig_cs |> R.reword_error Types.msg_of_error)
  >>= (function
      | [Signature_type detached_sig , _] -> Ok detached_sig
      | first_packet::_ ->
        error_msg (fun m -> m "detached signature expected; got %a"
                      pp_packet (fst first_packet))
      | [] -> error_msg (fun m -> m "No packets found in supposed detached sig")
      )

let new_transferable_secret_key
    ~(g : Nocrypto.Rng.g) ~(current_time : Ptime.t)
    version
    (root_key : Public_key_packet.private_key)
      (* TODO revocations *)
    (uncertified_uids : Uid_packet.t list) (* TODO revocations*)
    (* TODO user_attributes *)
    (priv_subkeys : Public_key_packet.private_key list) (* TODO revocations*)
  : (Signature.transferable_secret_key, [>]) result =
  if version <> V4 then error_msg (fun x -> x "wrong version %d" 3)
  else
  let () = Logs.debug (fun m -> m "trying to certify UIDs") in
  (* TODO create relevant signature subpackets *)
  uncertified_uids
  |> result_ok_list_or_error (fun uid ->
      Signature.certify_uid ~g ~current_time root_key uid
      >>| fun certification ->
      { Signature.uid ; certifications = [certification] }
  )
  >>= fun uids ->
  Logs.debug (fun m -> m "%d UIDs certified. moving on." (List.length uids));
  if uids = [] then
    error_msg (fun m ->m "No UIDs given. Need at least one.")
  else
  priv_subkeys |> result_ok_list_or_error
    (fun subkey ->
       Signature.certify_subkey ~g ~current_time root_key subkey
       >>| fun certification -> {Signature.secret_key = subkey
                                ; binding_signatures = [certification]
                                ; revocations = [] }
    ) >>| fun certified_subkeys ->
  ({ Signature.root_key
   ; uids
   ; secret_subkeys = certified_subkeys
   } : Signature.transferable_secret_key)

let serialize_uid_certifications (uids: Signature.uid list) =
  uids |>
  result_ok_list_or_error (fun {Signature.uid;certifications} ->
      serialize_packet V4 (Uid_packet uid) >>= fun uid_cs ->
      certifications |> result_ok_list_or_error (fun s ->
          serialize_packet V4 (Signature_type s))
      >>| fun certs_cs -> Cs.concat (uid_cs::certs_cs))

let serialize_transferable_secret_key version {Signature.root_key ; uids ; secret_subkeys} =
  let buf = Cs.W.create 2000 in
  serialize_packet version (Secret_key_packet root_key) >>| Cs.W.cs buf >>= fun () ->
  serialize_uid_certifications uids >>| Cs.concat >>| Cs.W.cs buf >>= fun () ->
  secret_subkeys |> result_ok_list_or_error
    (fun {Signature.secret_key;binding_signatures;revocations} ->
       serialize_packet V4 (Secret_key_subpacket secret_key) >>= fun key_cs ->
       (binding_signatures @ revocations)
       |> result_ok_list_or_error
         (fun s -> serialize_packet V4 (Signature_type s))
       >>| List.cons key_cs >>| Cs.concat
    ) >>| Cs.concat >>| Cs.W.cs buf >>= fun () ->
  Ok (Cs.W.to_cs buf)

let serialize_transferable_public_key (pk : Signature.transferable_public_key) =
  let open Signature in

  pk.revocations |> result_ok_list_or_error (fun rev ->
      serialize_packet V4 (Signature_type rev))
  >>| Cs.concat >>= fun revocations ->

  (* serialize UIDs and certifications: *)
  serialize_uid_certifications pk.uids >>| Cs.concat >>= fun uids_cs ->

  let user_attributes = Cs.create 0 in (* TODO serialize user attributes*)

  (* serialize subkeys, certifications, and optionally revocations *)
  pk.subkeys |> result_ok_list_or_error
    (fun {key;binding_signatures;revocations} ->
       serialize_packet V4 (Public_key_subpacket key) >>= fun key_cs ->
       (binding_signatures @ revocations) |> result_ok_list_or_error
         (fun s -> serialize_packet V4 (Signature_type s))
       >>| Cs.concat >>| fun sig_cs ->
       Cs.concat [key_cs ; sig_cs]
    ) >>| Cs.concat >>= fun subkeys_cs ->

  serialize_packet V4 (Public_key_packet pk.root_key) >>| fun pk_cs ->
  (Cs.concat [ pk_cs
             ; revocations
             ; uids_cs
             ; subkeys_cs ])
