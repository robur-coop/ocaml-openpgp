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
  | User_attribute_packet of User_attribute_packet.t
  | Encrypted_packet of Encrypted_packet.encrypted Encrypted_packet.t
  | Public_key_encrypted_session_packet of Public_key_encrypted_session_packet.t

let packet_tag_of_packet = begin function
  | Signature_type _ -> Signature_tag
  | Public_key_packet _ -> Public_key_tag
  | Public_key_subpacket _ -> Public_subkey_tag
  | Uid_packet _ -> Uid_tag
  | Secret_key_packet _ -> Secret_key_tag
  | Secret_key_subpacket _ -> Secret_subkey_tag
  | Trust_packet _ -> Trust_packet_tag
  | User_attribute_packet _ -> User_attribute_tag
  | Encrypted_packet _ -> Encrypted_packet_tag
  | Public_key_encrypted_session_packet _ ->
    Public_key_encrypted_session_packet_tag
  end

let encode_ascii_armor (armor_type:ascii_packet_type) (buf : Cs.t)
  : (Cs.t, [> R.msg]) result=
  let newline = Cs.of_string "\r\n" in
  let rec base64_encoded (acc:Cs.t list) buf_tl =
    (* 54 / 3 * 4 = 72; output chunks of 72 chars.
     * The last line will not be newline-terminated. *)
    Cs.split_result buf_tl (min (Cs.len buf_tl) 54)
    >>= fun (chunk, next_tl) ->
    if Cs.len chunk <> 0 then
      base64_encoded (Cs.of_cstruct
                        (Nocrypto.Base64.encode
                           (Cs.to_cstruct chunk)) :: acc) next_tl
    else
      match acc with
      | [] -> Ok (Cs.create 0) (* if input was empty, return empty output *)
      | acc_hd::acc_tl ->
        let end_lines = List.map (fun line ->
            Cs.concat [line;newline]) acc_tl in
        Ok (Cs.concat @@ List.rev (acc_hd::end_lines))
  in
  let cs_armor_magic = string_of_ascii_packet_type armor_type |> Cs.of_string in
  base64_encoded [] buf >>| fun encoded_buf ->
    Cs.concat
    [ Cs.of_string "-----BEGIN PGP " ; cs_armor_magic ; Cs.of_string "-----\r\n"
      (*; TODO headers*)
    ; newline (* <-- end of headers*)

    ; encoded_buf
    ; newline

    (* CRC24 checksum: *)
    ; Cs.of_string "=";
      Nocrypto.Base64.encode
        (crc24 buf |> Cs.to_cstruct) |> Cs.of_cstruct ; newline

    (* END / footer: *)
    ; Cs.of_string "-----END PGP " ; cs_armor_magic ; Cs.of_string "-----\r\n"
    ]

let decode_ascii_armor ~allow_trailing (buf : Cs.t) =
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
  Cs.e_split (`Msg "`Invalid header")
    begin_header (String.length "-----BEGIN PGP ")
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

  Logs.debug (fun m -> m "Skipping armor headers (like \"Version:\"; \
                          not handled in this implementation)") ;
  let rec skip_headers buf_tl =
    match Cs.next_line ~max_length buf_tl  with
    | `Last_line not_body_cs ->
      error_msg (fun m -> m "Missing armored body, expected here: %a"
                    Cs.pp_hex not_body_cs)
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
      Nocrypto.Base64.decode (Cs.to_cstruct cs)
      |> R.of_option ~none:(fun()->
          error_msg (fun m -> m "Cannot base64-decode body line: %a"
                        Cs.pp_hex cs ))
      >>| Cs.of_cstruct
    in
    begin match Cs.next_line ~max_length:76 tl with
      | `Last_line not_end_cs ->
        error_msg (fun m -> m "Unexpected end of armored body: %a"
                  Cs.pp_hex not_end_cs)
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
                 Cs.pp_hex target_crc Cs.pp_hex decoded_crc24)
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

  begin if allow_trailing
    then Ok ()
    else begin
      Logs.debug (fun m -> m "Checking that there is no data after the footer");
      let rec loop buf =
        match Cs.next_line ~max_length buf with
        | `Next_tuple (this,tl) ->
          Cs.e_is_empty (`Msg "packet contains data after footer") this
          >>= fun () -> loop tl
        | `Last_line this ->
          Cs.e_is_empty (`Msg "last armor line is not empty") this
      in loop buf
    end
  end >>= fun () ->

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
  Ok (pkt_type, decoded, buf)

let parse_packet_body packet_tag pkt_body
  : (packet_type, [> `Msg of string | `Incomplete_packet ]) result =
  begin match packet_tag with
    | Compressed_data_packet_tag ->
      R.error_msg "Compressed data packet not allowed in this context."
    | Literal_data_packet_tag ->
      R.error_msg "Literal data packet not allowed in this context."
    | Encrypted_packet_tag ->
      Encrypted_packet.parse_packet pkt_body >>| fun pkt -> Encrypted_packet pkt
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
      User_attribute_packet.parse_packet
        pkt_body >>| fun attr -> User_attribute_packet attr
    | Public_key_encrypted_session_packet_tag ->
      Public_key_encrypted_session_packet.parse_packet pkt_body
      >>| fun session_pkt -> Public_key_encrypted_session_packet session_pkt

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
    Fmt.pf ppf "Trust packet (ignored): @[%a@]" Cs.pp_hex cs
  | User_attribute_packet pkt ->
    Fmt.pf ppf "User attribute packet: %a" User_attribute_packet.pp pkt
  | Encrypted_packet pkt ->
    Fmt.pf ppf "Encrypted packet %a" Encrypted_packet.pp pkt
  | Public_key_encrypted_session_packet pkt ->
    Fmt.pf ppf "Encrypted packet %a" Public_key_encrypted_session_packet.pp pkt
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
  | User_attribute_packet pkt -> User_attribute_packet.hash pkt hash_cb version
  | Encrypted_packet pkt -> (* TODO*)
    Encrypted_packet.hash pkt hash_cb version
  | Public_key_encrypted_session_packet pkt ->
    Public_key_encrypted_session_packet.hash pkt hash_cb version
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
    | User_attribute_packet pkt -> User_attribute_packet.serialize pkt
    | Encrypted_packet pkt -> Encrypted_packet.serialize pkt
    | Public_key_encrypted_session_packet pkt ->
      Public_key_encrypted_session_packet.serialize pkt
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
  Logs.debug
    (fun m -> m "serialized packet@[<v>@ %a@ header: %a@ contents: %a@]"
        pp_packet pkt
        Cs.pp_hex header_cs
        Cs.pp_hex body_cs );
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
    { certifications : Signature_packet.t list ;
      attributes : User_attribute_packet.t
    }

  type subkey =
    { key : Public_key_packet.t
    ; binding_signatures : Signature_packet.t list
    (* plus optionally revocation signatures: *)
    ; revocations : Signature_packet.t list
    }

  let pp_subkey fmt key =
    Fmt.pf fmt "subkey {  @[<v>key: @[%a@]@,binding: \
                [@[%a@]]@,revocations: [@[%a@]]@]}"
      Public_key_packet.pp key.key
      Fmt.(list ~sep:(unit "@,|  ") Signature_packet.pp) key.binding_signatures
      Fmt.(list ~sep:(unit "@,|  ") Signature_packet.pp) key.revocations

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

  let key_can_be_used_in_context key_cb kuf_cb key certifications =
    (* TODO we ignore revocations here since a revoked key should never
       be constructed? *)
    key_cb key
    && List.exists (fun signature ->
        begin match Signature_packet.SubpacketMap.get Key_usage_flags
                      signature.subpacket_data with
        | Ok Key_usage_flags kuf -> kuf_cb kuf
        | Error _ -> true (* if no KUF then assume it's ok *)
        end) certifications

  let can_encrypt = key_can_be_used_in_context Public_key_packet.can_encrypt
      (fun kuf -> kuf.encrypt_communications)

  let can_sign = key_can_be_used_in_context Public_key_packet.can_sign
      (fun kuf -> kuf.sign_data)

  let secret_eligible_keys key_capability_cb tsk =
    ( (List.map (fun (uid:uid) -> tsk.root_key, uid.certifications) tsk.uids)
      @ List.map (fun (x:private_subkey) ->
          x.secret_key, x.binding_signatures) tsk.secret_subkeys)
    |> List.filter (fun (key, sigs) ->
        key_capability_cb (Public_key_packet.public_of_private key) sigs)
    |> List.map fst

  let public_eligible_keys key_capability_cb (tpk:transferable_public_key) =
    ( (List.map (fun (uid:uid) -> tpk.root_key, uid.certifications) tpk.uids)
      @ List.map (fun (x:subkey) ->
          x.key, x.binding_signatures) tpk.subkeys)
    |> List.filter (fun (key, sigs) -> key_capability_cb key sigs)
    |> List.map fst

  let check_signature_transferable current_time (tpk:transferable_public_key)
      hash_final signature  =
    let pks = public_eligible_keys can_sign tpk in
    check_signature current_time pks hash_final signature
    |> R.reword_error (function
        | `Incomplete_packet ->  R.msg "TODO Incomplete packet"
        | `Msg _ as msg -> msg)

  let verify_detached_cb ~current_time (pk:transferable_public_key)
      (signature:t) (cb:(unit -> (Cs.t option, [> R.msg]) result))
  : ([ `Good_signature], [> R.msg ]) result =
    (* TODO check pk is valid *)
    true_or_error (signature.signature_type = Signature_of_binary_document)
      (fun m -> m "TODO not implemented: we do not handle the newline-\
                   normalized @,(->\\r\\n) signature_type.Signature_of_canonic\
                   al_text_document") >>= fun () ->
    digest_callback signature.hash_algorithm >>= fun (hash_cb, hash_final) ->
    Logs.debug (fun m -> m "hashing detached signature with callback...");
    let rec hash_loop () =
      cb () >>= function
      | None -> Ok signature
      | Some data -> hash_cb data ; hash_loop ()
    in hash_loop ()
    >>= fun _ -> hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->
    Logs.debug (fun m -> m "Checking detached signature");
    check_signature_transferable current_time pk hash_final signature

  let verify_detached_cs ~current_time tpk signature cs =
     digest_callback signature.hash_algorithm >>= fun (hash_cb, hash_final) ->
    true_or_error (signature.signature_type = Signature_of_binary_document)
      (fun m -> m "TODO not implemented: we do not handle the newline-\
                   normalized@,(->\\r\\n) signature_type.Signature_of_canon\
                   ical_text_document. In this case we got a %a"
          pp_signature_type signature.signature_type
      ) >>= fun () ->
    Logs.debug (fun m -> m "hashing detached signature with Cs.t ...");
    hash_cb cs ;
    hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->
    Logs.debug (fun m -> m "Checking detached signature");
    check_signature_transferable current_time tpk hash_final signature

  let check_signature_on_root_and_subkey ~current_time sig_types
                                          root_pk subkey t =
    true_or_error (List.exists (fun st -> st = t.signature_type) sig_types)
      (fun m -> m "Invalid signature type %a rejected, expecting one of @[%a@]"
          pp_signature_type t.signature_type
          Fmt.(list pp_signature_type) sig_types
      )
    >>= fun () ->

    (* set up hashing with this signature: *)
    digest_callback t.hash_algorithm >>= fun (hash_cb, hash_final) ->

    (* This signature is calculated directly on the
       primary key and subkey, and not on any User ID or other packets.*)
    hash_packet V4 hash_cb (Public_key_packet root_pk) >>= fun () ->
    hash_packet V4 hash_cb (Public_key_packet subkey.key) >>= fun () ->
    hash_packet V4 hash_cb (Signature_type t) >>= fun () ->
    let designated_keys =
      match t.signature_type with
      | Primary_key_binding_signature -> [subkey.key]
      | Subkey_binding_signature -> [root_pk]
      | Signature_directly_on_key
      | Key_revocation_signature
      | Subkey_revocation_signature ->
        Logs.warn (fun m -> m "check_signature_on_root_and_subkey: not \
                      implemented: %a" pp_signature_type t.signature_type); []
      | _ -> Logs.debug (fun m -> m "check_signature_on_root_and_subkey: \
                                     Unable to verify signature of type %a"
                            pp_signature_type t.signature_type); []
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
    | Public_key_packet.Elgamal_pubkey_asf _ ->
      Ok () (* no binding sig required for encryption keys *)
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
           >>= (function
               | (Embedded_signature embedded_sig) -> Ok embedded_sig
               | _ -> error_msg (fun m -> m "expected embedded signature TODO")
             )
           >>= Signature_packet.parse_packet ~allow_embedded_signatures:false
           >>= fun embedded_sig ->
             check_embedded_signature current_time root_pk
               embedded_sig { key = subkey
                            ; revocations = []; binding_signatures=[]}
           >>= fun `Good_signature -> R.ok ()
      end

  let sign ~(current_time : Ptime.t) signature_type
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
    true_or_error (public_key_algorithm <> RSA_encrypt_only)
      (fun m -> m "can't sign with rsa_encrypt_only") >>= fun () ->
    (* add Signature_creation_time with [current_time] if no creation time: *)
    let signature_subpackets :signature_subpacket SubpacketMap.t =
      let v4_fp = pk.Public_key_packet.v4_fingerprint in
      SubpacketMap.upsert Issuer_fingerprint (Issuer_fingerprint (V4,v4_fp))
        signature_subpackets
      |> SubpacketMap.upsert Issuer_keyid
        (Issuer_keyid (Cs.exc_sub v4_fp 12 8))
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
      let (r,s) =
        let (r,s) =
          Nocrypto.Dsa.sign ~mask:`Yes ~key (Cs.to_cstruct digest) in
        Cs.of_cstruct r, Cs.of_cstruct s
      in
      Ok (DSA_sig_asf {r = Types.mpi_of_cs_no_header r
                      ; s = mpi_of_cs_no_header s})
    | Public_key_packet.RSA_privkey_asf key ->
      Logs.debug (fun m -> m "sign: signing digest with RSA key") ;

      nocrypto_poly_variant_of_hash_algorithm hash_algorithm >>| fun hash ->
        (RSA_sig_asf { m_pow_d_mod_n =
                          Nocrypto.Rsa.PKCS1.sign ~mask:`Yes
                          ~hash
                          ~key (`Digest (Cs.to_cstruct digest))
                          |> Cs.of_cstruct |> mpi_of_cs_no_header
                     })
    | Public_key_packet.Elgamal_privkey_asf _ ->
      error_msg (fun m -> m "Cannot sign with El-Gamal key")
    end
    >>| fun algorithm_specific_data ->
    { signature_type ; public_key_algorithm ; hash_algorithm ;
      two_octet_checksum = Cs.exc_sub digest 0 2 ;
      algorithm_specific_data ; subpacket_data = signature_subpackets}

  let sign_detached_cb ~current_time tsk hash_algo ((hash_cb, _) as hash_tuple)
      io_cb =
    let keys = secret_eligible_keys can_sign tsk in
    (if [] = keys then R.error_msgf "" else Ok (List.hd keys)
    ) >>= fun signing_key ->
    let rec io_loop () =
      io_cb () >>= function
      | None -> Ok ()
      | Some data -> hash_cb data ; io_loop ()
    in
    io_loop () >>= fun () ->
    let subpackets = SubpacketMap.empty in
    sign ~current_time Signature_of_binary_document signing_key subpackets
         hash_algo hash_tuple

  let sign_detached_cs ~current_time tsk hash_algo target_cs =
    let keys = secret_eligible_keys can_sign tsk in
    (if [] = keys then R.error_msgf "" else Ok (List.hd keys)
    ) >>= fun signing_key ->
    let subpackets = SubpacketMap.empty (* TODO support expiry time *) in
    digest_callback hash_algo >>= fun ((hash_cb, _) as hash_tuple) ->
    hash_cb target_cs ;
    sign ~current_time
      Signature_of_binary_document
      signing_key subpackets
      hash_algo hash_tuple

  let with_default_signature_subpackets ?(expires : Ptime.Span.t option)
      (subpackets: signature_subpacket SubpacketMap.t) =
    (* TODO limit this function to only deal with certifications *)
    subpackets
    (* Tell peers about validity time constraints, if any: *)
    |> begin match expires with
      | Some expiry -> SubpacketMap.add_if_empty Key_expiration_time
                         (Key_expiration_time expiry)
      | None -> (fun kuf -> kuf) end
    (* Tell peers that we support MDC checking so they will at least SHA1
       their encrypted messages to us:*)
    |> SubpacketMap.add_if_empty Features (Features [Modification_detection])

  let certify_uid
      ~(current_time : Ptime.t)
      ?(expires : Ptime.Span.t option)
      (subpackets : signature_subpacket SubpacketMap.t)
      (priv_key : Public_key_packet.private_key) uid
    : (Signature_packet.t, [>]) result =
    (* UIDs (on the root TPK)*)
    (* TODO handle V3 *)
    begin match Public_key_packet.public_key_algorithm_of_asf
             priv_key.Public_key_packet.public.
               Public_key_packet.algorithm_specific_data with
    | RSA_encrypt_or_sign | RSA_sign_only | DSA -> Ok ()
    | ( RSA_encrypt_only | Elgamal_encrypt_only) as pk_alg
      -> R.error_msgf "can't certify UID with an encryption-only key %a"
           pp_public_key_algorithm pk_alg
    end >>= fun () ->
    (* TODO pick hash from priv_key.Preferred_hash_algorithms if present: *)
    let hash_algo = SHA384 in
    let subpackets : signature_subpacket SubpacketMap.t =
      (* TODO UIDs need Preferred_*; can't have KUF *)
      subpackets
      (* Tell peers about supported hashing algorithms: *)
      |> SubpacketMap.add_if_empty Preferred_hash_algorithms
        (Preferred_hash_algorithms [SHA384 ; SHA512 ; SHA256])
      (* Tell peers about supported compression algorithms: *)
      |> SubpacketMap.add_if_empty Preferred_compression_algorithms
        (Preferred_compression_algorithms [ ZLIB ; ZIP ; Uncompressed ])
      (* Tell peers about the ciphers we support: *)
      |> SubpacketMap.add_if_empty Preferred_symmetric_algorithms
        (Preferred_symmetric_algorithms [AES256 ; AES192 ; AES128])
      |>  with_default_signature_subpackets ?expires
    in
    digest_callback hash_algo >>= fun ((hash_cb, _) as hash_tuple) ->
    Logs.debug (fun m -> m "certify_uid: hashing public key packet") ;
    hash_packet V4 hash_cb (Public_key_packet
      (Public_key_packet.public_of_private priv_key)) >>= fun () ->
    Logs.debug (fun m -> m "certify_uid: hashing UID packet") ;
    hash_packet V4 hash_cb (Uid_packet uid) >>= fun () ->
    Logs.debug (fun m -> m "certify_uid: producing signature") ;
    sign ~current_time
      Positive_certification_of_user_id_and_public_key_packet
      priv_key subpackets
      hash_algo hash_tuple

  let certify_subkey ~current_time
      ?(expires : Ptime.Span.t option)
      ~key_usage_flags
      (priv_key:Public_key_packet.private_key) subkey
    : (Signature_packet.t, [>]) result =
    (* TODO handle V3 *)
    (* TODO pick hash from priv_key.Preferred_hash_algorithms if present: *)
    let hash_algo = SHA384 in
    begin
      let open Public_key_packet in
      let subkey_pk = public_of_private subkey in
      match (can_sign subkey_pk), (can_encrypt subkey_pk), key_usage_flags with
    (* TODO verify that unimpl = [\000]*)
      | false, _, kuf when (kuf.certify_keys || kuf.sign_data
                            || kuf.authentication) ->
        R.error_msgf "Cannot create a certifyin/signing/authenticating key \
                      for a key type that is unable to sign data: %a %a"
          pp_key_usage_flags kuf
          Public_key_packet.pp_secret subkey
      | _, false, kuf when(kuf.encrypt_communications || kuf.encrypt_storage) ->
        R.error_msgf "Cannot create a encryption key \
                      for a key type that is unable to encrypt data: %a %a"
          pp_key_usage_flags kuf
          Public_key_packet.pp_secret subkey
      | true, true, _ -> Ok ()
      | _, _, { unimplemented = ['\000'] } -> Ok ()
      | _ -> R.error_msgf "Cannot create a key with unknown unimplemented KUF \
                           flags for a keytype that is not able to both \
                           sign and encrypt data: %a %a"
          pp_key_usage_flags key_usage_flags
          Public_key_packet.pp_secret subkey
    end >>= fun () ->
    let subpackets =
      (* Can't have Preferred_*; should have KUF *)
      SubpacketMap.empty
      |> SubpacketMap.upsert Key_usage_flags (Key_usage_flags key_usage_flags)
      |> with_default_signature_subpackets ?expires
    in
    digest_callback hash_algo >>= fun ((hash_cb, _) as hash_tuple) ->
    hash_packet V4 hash_cb
      (Public_key_packet
         (Public_key_packet.public_of_private priv_key)) >>= fun () ->
    (if key_usage_flags.certify_keys || key_usage_flags.authentication then
       R.error_msgf "Creating a certifying subkey requires an \
                     Embedded_signature which is currently not implemented.\
                     Please file a bug report."
     else Ok () ) >>= fun () ->
    hash_packet V4 hash_cb (Public_key_packet
      (Public_key_packet.public_of_private subkey)) >>= fun () ->
    sign ~current_time
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
    digest_callback signature.hash_algorithm >>= fun (hash_cb, hash_final) ->
    (* TODO handle version V3 *)
    hash_packet V4 hash_cb (Public_key_packet root_pk) >>= fun () ->
    hash_packet V4 hash_cb uid >>= fun () ->
    hash_packet V4 hash_cb (Signature_type signature) >>= fun () ->

    (* Check that the root key has not expired with this UID *)
    ( public_key_not_expired current_time root_pk signature
      |> log_failed (fun m -> m "root key expired with this UID")
    ) >>= fun () ->

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
      packets |> inner_loop
        (certifications |> List.filter
          (fun certification -> match validation_cb obj certification with
            | Ok `Good_signature -> true | _ -> false
             (* The certifications can be made by anyone,
                we are only concerned with the ones made by the root_pk *)
          ) |> begin function
               | [] -> log_msg (fun m -> m "Skipping %a due to lack of valid \
                                            certifications" pp_packet obj) acc
               | valid_certifications -> ((obj, valid_certifications)::acc)
        end)
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
  (* TODO return certifications *)
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
      Ok ( {root_key ; uids; secret_subkeys}
         , packets)
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
          Logs.debug (fun m -> m "@[<v>find_subkeys_and_their sigs:@ %a@]"
                     pp_subkey subkey) ;
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
  let decoded = decode_ascii_armor ~allow_trailing:false cs in
  begin match armored, decoded with
    | (Some true | None), Ok (my_armor, cs, trailing)
      when my_armor = armor_type -> Ok cs
    | None , Error _->
      Logs.err(fun m -> m "Failed decoding ASCII armor %a, parsing as \
                           raw instead"
                  pp_ascii_packet_type armor_type ) ; Ok cs
    | _ -> error_msg
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
  >>= parse_packets
  >>= (fun sec_cs -> Signature.root_sk_of_packets ~current_time sec_cs )

type encrypted_message =
  { public_sessions : Public_key_encrypted_session_packet.t list ;
    symmetric_session : unit list ; (* TODO *)
    data : Encrypted_packet.encrypted Encrypted_packet.t ;
    signatures : Signature.t list ;
  }

let decrypt_message ~current_time
    ~(secret_key:Signature.transferable_secret_key)
    {public_sessions ; data; signatures ; symmetric_session = _} =
  if signatures <> [] then
    Logs.warn (fun m -> m "%s: TODO check signatures" __LOC__) ;
  let trial_decryption_candidates =
    List.map
      (fun key ->
         let open Public_key_encrypted_session_packet in
         key, List.filter (matches_key key) public_sessions)
      (Signature.(secret_eligible_keys can_encrypt) secret_key)
  in
  let rec trial_decrypt = function
    | [] -> R.error_msgf "None of our secret keys could decrypt the message"
    | (key, sessions)::candidate_tl ->
      let open Public_key_encrypted_session_packet in
      let rec trial_decrypt_session = function
        | [] -> R.error_msgf "No sessions were encrypted for this key"
        | session::session_tl ->
          Logs.debug (fun m -> m "Trying to decrypt session %a using key %a"
                         pp session Public_key_packet.pp_secret key);
          begin match decrypt key session with
            | Error _ -> trial_decrypt_session session_tl
            | Ok _ as res -> res
          end
      in
      begin match trial_decrypt_session sessions with
        | Ok _ as res ->
          Logs.info (fun m -> m "Decrypted using key ID %s"
                        Public_key_packet.(v4_key_id_hex
                                           @@ public_of_private key)) ;
          res
        | Error _ -> trial_decrypt candidate_tl
      end
  in trial_decrypt trial_decryption_candidates >>= fun (sym_algo, dec) ->
  Logs.debug (fun m -> m "decrypted message using %a"
                 pp_symmetric_algorithm sym_algo);
  Encrypted_packet.decrypt ~key:dec data >>= fun payload ->
  Logs.debug (fun m -> m "Decrypted: %a" Cs.pp_hex payload);
  let consume_all payload =
    Types.consume_packet_header payload >>= fun (header, payload) ->
    Logs.debug (fun m -> m "Got header %a" Types.pp_packet_header header );
    Types.consume_packet_length header.Types.length_type payload
    >>= fun (payload, rest) ->
    Types.true_or_error (0 = Cs.len rest)
      (fun m -> m "Extraneous data in decrypted payload: %a" Cs.pp_hex rest)
    >>| fun () -> header, payload
  in
  let handle_literal payload =
      Literal_data_packet.parse payload
      >>= fun (Literal_data_packet.In_memory_t (final_state, acc) as pkt) ->
      let msg = String.concat "" acc in
      Logs.debug (fun m -> m "ph: %a@ msg:@,%S"
                     Literal_data_packet.pp pkt msg) ;
      Ok (final_state, msg)
  in
  consume_all payload >>= fun (header,payload) ->
  begin match header.Types.packet_tag with
    | Types.Literal_data_packet_tag ->
      handle_literal payload
    | Types.Compressed_data_packet_tag ->
      Logs.debug (fun m -> m "compressed packet:@,%a" Cs.pp_hex payload);
      Compressed_packet.parse
        (Cs.R.of_cs (R.msg "Unexpected end of compressed plaintext") payload)
      >>| Cs.of_string >>= fun decompressed ->
      Logs.debug (fun m -> m "decompressed: %a" Cs.pp_hex decompressed);
      consume_all decompressed >>| snd >>= fun literal_data ->
      Logs.debug (fun m -> m "literal_data: %a" Cs.pp_hex literal_data);
      handle_literal literal_data
    (* TODO check that header does indeed contain a literal data packet*)
    | unexpected_tag -> R.error_msgf "Expected Literal Data in message, got %a"
                          Types.pp_packet_tag unexpected_tag
  end

let encode_message ?(armored=true) (message:encrypted_message) =
  result_ok_list_or_error
    (fun ps -> serialize_packet V4 (Public_key_encrypted_session_packet ps))
        message.public_sessions
  >>= fun pk_sessions ->
  (*message.symmetric_session ; (*TODO*)*)
  serialize_packet V4 (Encrypted_packet message.data) >>= fun data ->
  result_ok_list_or_error
    (fun s -> serialize_packet V4 (Signature_type s))
    message.signatures >>= fun sigs ->
  let encoded = Cs.concat [Cs.concat pk_sessions; data; Cs.concat sigs] in
  if armored then
    encode_ascii_armor Ascii_message encoded
  else
    Ok encoded

let decode_message ?armored cs
  : (encrypted_message, [> R.msg]) result =
  (* TODO RFC 4880 #section-11.3*)
  armored_or_not ?armored Ascii_message cs
  >>= parse_packets >>= fun packets ->
  let rec loop (state : [< `Container | `Data
                        | `Trailing of 'a Encrypted_packet.t * 'b list])
                ~public packets =
    let session_packet = function
      | (Public_key_encrypted_session_packet pkt, _)::tl ->
        loop state ~public:(pkt::public) tl
      | (Encrypted_packet _, _)::_ ->
        loop `Data ~public packets
      | (pkt, _)::_ -> R.error_msgf "Unexpected packet while decoding message \
                                     [public keys]: %a" pp_packet pkt
      | [] -> R.error_msgf "Unexpected end of stream while decoding message \
                           looking for session key data packets"
    in
    let data_packet = function
      | (Encrypted_packet pkt, _cs)::tl ->
        loop (`Trailing (pkt,[])) ~public tl
      | (pkt, _)::_ -> R.error_msgf "Unexpected packet while decoding message \
                                     [encrypted data]: %a" pp_packet pkt
      | [] -> R.error_msgf "Unexpected end of stream while decoding message \
                           looking for encrypted data packets"
    in
    let trailing_packet pkt s_acc = function
      | (Signature_type x, (*TODO*) _cs ) :: tl ->
        loop (`Trailing (pkt, x::s_acc)) ~public tl
      | (pkt, _)::_ -> R.error_msgf "Unexpected packet while decoding message \
                                     [trailing packets]: %a" pp_packet pkt
      | [] -> Ok (public, pkt, s_acc)
    in
    match state with
    | `Container -> session_packet packets
    | `Data -> data_packet packets
    | `Trailing (pkt, sigs)-> trailing_packet pkt sigs packets
  in loop `Container ~public:[] packets
  >>=  fun (public_sessions, data, signatures) ->
  true_or_error (public_sessions <> [])
    (fun m -> m "This message contains no public key slots") >>= fun () ->
  begin if signatures = [] then
      Logs.warn (fun m -> m "%s: Message is not signed" __LOC__)
  end ;
  Ok { public_sessions ; symmetric_session = [] ; data; signatures }

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

let encrypt_message ?rng
    ~current_time (* time is needed in case we want to sign it*)
    ~(public_keys:Signature.transferable_public_key list)
    payload : (encrypted_message, [> R.msg]) result=
  true_or_error ([] <> public_keys)
    (fun m -> m "Refusing to encrypt message without recipients") >>= fun () ->
  (* TODO use Preferred_symmetric_algorithms *)
  Public_key_encrypted_session_packet.create_key ?g:rng AES256
  >>= fun symmetric_key ->
  result_ok_list_or_error
    (fun tpk ->
       match Signature.public_eligible_keys Signature.can_encrypt tpk with
     | [] -> R.error_msgf "No encryption key provided for TPK TODO print id"
     | recipient::_ ->
       Public_key_encrypted_session_packet.create ?g:rng recipient symmetric_key
    ) public_keys >>= fun public_sessions ->
  (* consume_packet_header -> packet_header_of_char *)
  (* consume_packet_length -> *)
  (*  serialize_packet V4 (Literal_data_packet payload) >>= fun encoded_payload ->*)
  Encrypted_packet.encrypt ?g:rng ~symmetric_key:(snd symmetric_key)
    payload >>= fun data ->
  Ok { public_sessions; symmetric_session = [] ; data ; signatures = [] }

let new_transferable_secret_key
    ~(current_time : Ptime.t)
    version
    (root_key : Public_key_packet.private_key)
    (* TODO revocations *)
    (uncertified_uids : Uid_packet.t list) (* TODO revocations*)
    (* TODO user_attributes *)
    (priv_subkeys : (Public_key_packet.private_key * key_usage_flags) list)
  (* TODO revocations*)
  : (Signature.transferable_secret_key, [>]) result =
  if version <> V4 then error_msg (fun x -> x "wrong version %d" 3)
  else
  let () = Logs.debug (fun m -> m "trying to certify UIDs") in
  (* TODO create expiry subpacket *)
  let subpackets =
    let open Signature_packet in
    SubpacketMap.empty
    |> SubpacketMap.add_if_empty Key_usage_flags
      (Signature_packet.Key_usage_flags
         { certify_keys = true ; unimplemented = ['\000']
         ; sign_data = false ; encrypt_communications = false
         ; encrypt_storage = false ; authentication = false })
  in
  uncertified_uids
  |> result_ok_list_or_error (fun uid ->
      Signature.certify_uid ~current_time subpackets root_key uid
      >>| fun certification ->
      { Signature.uid ; certifications = [certification] }
  )
  >>= fun uids ->
  Logs.debug (fun m -> m "%d UIDs certified. moving on." (List.length uids));
  if uids = [] then
    error_msg (fun m ->m "No UIDs given. Need at least one.")
  else
  priv_subkeys |> result_ok_list_or_error
    (fun (subkey, key_usage_flags) ->
       Signature.certify_subkey ~current_time ~key_usage_flags root_key subkey
       >>| fun certification -> {Signature.secret_key = subkey
                                ; binding_signatures = [certification]
                                ; revocations = [] }
    ) >>| fun certified_subkeys ->
  ({ Signature.root_key
   ; uids
   ; secret_subkeys = certified_subkeys
   } : Signature.transferable_secret_key)

let serialize_user_attributes (attrs : Signature.user_attribute list) =
  attrs |>
  result_ok_list_or_error (fun {Signature.certifications; attributes} ->
      serialize_packet V4 (User_attribute_packet attributes) >>= fun attr_cs ->
      certifications |> result_ok_list_or_error
        (fun s -> serialize_packet V4 (Signature_type s)
        ) >>| fun certs_cs ->
      Cs.concat (attr_cs::certs_cs)
    )

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

  serialize_user_attributes pk.user_attributes >>| Cs.concat >>=
  fun user_attributes_cs ->

  (* serialize subkeys, certifications, and optionally revocations *)
  pk.subkeys |> result_ok_list_or_error
    (fun {key;binding_signatures;revocations} ->
       serialize_packet V4 (Public_key_subpacket key) >>= fun key_cs ->
       (binding_signatures @ revocations) |> result_ok_list_or_error
         (fun s -> serialize_packet V4 (Signature_type s))
       >>| Cs.concat >>| fun sig_cs ->
       Cs.concat [key_cs ; sig_cs]
    ) >>| Cs.concat >>= fun subkeys_cs ->

  (* Primary-Key
       [Revocation Self Signature]
       [Direct Key Signature...]
        User ID [Signature ...]
       [User ID [Signature ...] ...]
       [User Attribute [Signature ...] ...]
       [[Subkey [Binding-Signature-Revocation]
               Primary-Key-Binding-Signature] ...]
  *)

  serialize_packet V4 (Public_key_packet pk.root_key) >>| fun pk_cs ->
  (Cs.concat [ pk_cs
             ; revocations
             ; uids_cs
             ; user_attributes_cs
             ; subkeys_cs ])
