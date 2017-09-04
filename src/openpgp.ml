open Rresult
open Types

type packet_type =
  | Signature_type of Signature_packet.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t

let packet_tag_of_packet = begin function
  | Signature_type _ -> Signature_tag
  | Public_key_packet _ -> Public_key_tag
  | Public_key_subpacket _ -> Public_subkey_tag
  | Uid_packet _ -> Uid_tag
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
    | `Last_line _ -> Error `Invalid
  end
  >>= fun (begin_header, buf) ->

  (* check that it starts with a -----BEGIN... *)
  Cs.e_split `Invalid begin_header (String.length "-----BEGIN PGP ")
  >>= fun (begin_pgp, begin_tl) ->
  Cs.e_equal_string `Invalid "-----BEGIN PGP " begin_pgp >>= fun () ->

  (* check that it ends with five dashes: *)
  Cs.e_split `Invalid begin_tl (Cs.len begin_tl -5)
  >>= fun (begin_type , begin_tl) ->
  Cs.e_equal_string `Invalid "-----" begin_tl >>= fun () ->

  (* check that we know how to handle this type of ascii-armored message: *)
  begin match Cs.to_string begin_type with
      | "PUBLIC KEY BLOCK" -> Ok Ascii_public_key_block
      | "SIGNATURE" -> Ok Ascii_signature
      | "MESSAGE" -> Ok Ascii_message
      | "PRIVATE KEY BLOCK" -> Ok Ascii_private_key_block
      | _ -> Error `Invalid_key_type (*TODO better error*)
  end
  >>= fun pkt_type ->

  (* skip additional headers (like "Version:") *)
  let rec skip_headers buf_tl =
    begin match Cs.next_line ~max_length buf_tl  with
      | `Last_line _ -> Error `Missing_body
      | `Next_tuple pair -> Ok pair
    end
    >>= fun (header,buf_tl) ->
    if Cs.len header = 0 then
      R.ok buf_tl
    else begin
      (* skip to next*)
      Logs.debug (fun m -> m "Skipping header: %S" (Cs.to_string header));
      skip_headers buf_tl
    end
  in
  skip_headers buf
  >>= fun body ->

  let rec decode_body acc tl : (Cs.t*Cs.t,[> `Invalid]) result =
    let b64_decode cs =
      Nocrypto.Base64.decode cs
      |> R.of_option ~none:(fun()-> Error `Invalid)
    in
    begin match Cs.next_line ~max_length:73 tl with
      | `Last_line _ -> R.error `Invalid (*TODO better error*)
      | `Next_tuple (cs,tl) when Some 0 = Cs.index_opt cs '=' ->
        (* the CRC-24 starts with an =-sign *)
        Cs.e_split ~start:1 `Invalid cs 4
        >>= fun (b64,must_be_empty) ->
        if Cs.len must_be_empty <> 0 then Error `Invalid
        else
        b64_decode b64 >>= fun target_crc ->
        Logs.debug (fun m -> m "target crc: %s" (Cs.to_hex target_crc));
        begin match List.rev acc |> Cs.concat with
          | decoded when Cs.equal target_crc (crc24 decoded) ->
            Ok (decoded, tl)
          | _ -> Error `Invalid_crc24
        end
      | `Next_tuple (cs,tl) ->
        b64_decode cs >>= fun decoded ->
        decode_body (decoded::acc) tl
    end
  in decode_body [] body
  >>= fun (decoded, buf) ->

  (* Now we should be at the last line. *)
  begin match Cs.next_line ~max_length buf with
    | `Next_tuple ok -> Ok ok
    | `Last_line cs -> Ok (cs, Cs.create 0)
  end
  >>= fun (end_line, buf) ->
  Cs.e_find_string_list `Invalid ["\n";"\r\n";""] buf
  >>= fun _ ->

  begin match pkt_type with
  | Ascii_public_key_block ->
    Cs.e_equal_string `Missing_end_block "-----END PGP PUBLIC KEY BLOCK-----" end_line
  | Ascii_signature ->
    Cs.e_equal_string `Missing_end_block "-----END PGP SIGNATURE-----" end_line
  | Ascii_message ->
    Cs.e_equal_string `Missing_end_block "-----END PGP MESSAGE-----" end_line
  | Ascii_private_key_block ->
    Cs.e_equal_string `Missing_end_block "-----END PGP PRIVATE KEY BLOCK-----" end_line
  | Ascii_message_part_x _
  | Ascii_message_part_x_of_y _ ->
     Error `Malformed (* TODO `Not_implemented *)
  end
  >>= fun () ->
  Ok (pkt_type, decoded)

let parse_packet_body packet_tag pkt_body : (packet_type,'error) result =
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
    | Secret_key_tag
    | Secret_subkey_tag
    | User_attribute_tag ->
      R.error (`Unimplemented_algorithm 'P') (*TODO should have it's own (`Unimplemented of [`Algorithm of char | `Tag of char | `Version of char])*)
  end

let pp_packet ppf = begin function
  | Public_key_packet pkt -> Public_key_packet.pp ppf pkt
  | Public_key_subpacket pkt -> Public_key_packet.pp ppf pkt
  | Uid_packet pkt -> Uid_packet.pp ppf pkt
  | Signature_type pkt -> Signature_packet.pp ppf pkt
  end

let hash_packet version hash_cb = begin function
  | Uid_packet pkt -> Uid_packet.hash pkt hash_cb version
  | Public_key_packet pkt ->
      Public_key_packet.hash_public_key
        (Public_key_packet.serialize version pkt) hash_cb
  end

let next_packet (full_buf : Cs.t) :
  ((packet_tag_type * Cs.t * Cs.t) option,
   [>`Invalid_packet
   | `Unimplemented_feature of string
   | `Incomplete_packet]) result =
  if Cs.len full_buf = 0 then Ok None else
  consume_packet_header full_buf
  |> R.reword_error (function
      |`Incomplete_packet as i -> i
      |`Invalid_packet_header -> `Invalid_packet)
  >>= begin function
  | { length_type ; packet_tag; _ } , pkt_header_tl ->
    consume_packet_length length_type pkt_header_tl
    |> R.reword_error (function
        | `Invalid_length -> `Invalid_packet
        | `Incomplete_packet as i -> i
        | `Unimplemented_feature_partial_length ->
      `Unimplemented_feature "partial length")
      >>= fun (pkt_body, next_packet) ->
      Ok (Some (packet_tag , pkt_body, next_packet))
  end

let parse_packets cs : (('ok * Cs.t) list, int * 'error) result =
  (* TODO: 11.1.  Transferable Public Keys *)
  let rec loop acc cs_tl =
    next_packet cs_tl
    |> R.reword_error (fun a -> cs_tl.Cstruct.off, a)
    >>= begin function
      | Some (packet_type , pkt_body, next_tl) ->
        Logs.debug (fun m -> m "Will read a %a packet" pp_packet_tag packet_type);
        (parse_packet_body packet_type pkt_body
        |> R.reword_error (fun e -> List.length acc , e))
        >>= fun parsed ->
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
    ; signature : Signature_packet.t
    (* plus optionally a revocation signatures *)
    ; revocation : Signature_packet.t option
    }

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

  let check_signature_transferable current_time pk hash_final signature =
    let pks = pk.root_key :: (pk.subkeys |> List.map (fun k -> k.key)) in
    (* ^-- TODO filter out non-signing-keys*)
    check_signature current_time pks hash_final signature

  let verify_detached_cb ~current_time (pk:transferable_public_key)
      (signature:t) (cb:(unit -> (Cs.t option,'error) result))
  : ('ok, 'error) result =
    (* TODO check pk is valid *)
    if signature.signature_type <> Signature_of_binary_document then
      (* TODO not implemented: we don't handle the newline-normalized (->\r\n)
              signature_type.Signature_of_canonical_text_document *)
      Error `Invalid_signature
    else
    let (hash_cb, hash_final) =
      Signature_packet.digest_callback signature.hash_algorithm
    in
    let rec hash_loop () =
      cb () >>= function
      | None -> Ok signature
      | Some data -> hash_cb data ; hash_loop ()
    in hash_loop ()
    >>= construct_to_be_hashed_cs >>| hash_cb >>= fun () ->
    check_signature_transferable current_time pk hash_final signature

  let check_embedded_signature current_time pk t subkey =
    (* RFC 4880: 0x19: Primary Key Binding Signature
       This signature is a statement by a signing subkey, indicating
       that it is owned by the primary key and subkey.  This signature
       is calculated the same way as a 0x18 signature: directly on the
        primary key and subkey, and not on any User ID or other packets. *)
    begin match t.signature_type <> Primary_key_binding_signature with
      | true ->
        Logs.debug (fun m -> m "Rejecting embedded signature with invalid signature_type");
        R.error `Invalid_signature
      | false -> R.ok ()
    end >>= fun () ->

    (* set up hashing with this signature: *)
    let (hash_cb, hash_final) =
      Signature_packet.digest_callback t.hash_algorithm
    in
    (* This signature is calculated directly on the
       primary key and subkey, and not on any User ID or other packets.*)
    hash_packet V4 hash_cb (Public_key_packet pk);
    hash_packet V4 hash_cb (Public_key_packet subkey) ;
    construct_to_be_hashed_cs t >>| hash_cb >>= fun () ->
    check_signature current_time [subkey] hash_final t
    |> R.reword_error (fun err ->
        Logs.debug (fun m -> m "Rejecting invalid embedded signature");
        err)
    >>= fun `Good_signature ->
    Logs.debug (fun m -> m "Accepting embedded signature");
    Ok `Good_signature

  let root_pk_of_packets (* TODO aka root_key_of_packets *)
    ~current_time
    (packets : (packet_tag_type * Cs.t) list)
  : (transferable_public_key * (packet_tag_type * Cs.t) list,
   [> `Extraneous_packets_after_signature
   | `Incomplete_packet
   | `Invalid_packet
   | `Invalid_length
   | `Unimplemented_feature_partial_length
   | `Invalid_signature
   | `Unimplemented_version of char
   | `Unimplemented_algorithm of char
   | `Invalid_mpi_parameters of Types.mpi list
   ]
  ) result
  =
  (* RFC 4880: 11.1 Transferable Public Keys *)
  (* this function imports the output of gpg --export *)

  (* this would be a good place to wonder what kind of crack the spec people smoked while writing 5.2.4: Computing Signatures...*)
  let debug_packets packets =
    (* TODO learn how to make pretty printers *)
    let pp_error ppf = function
      | `Incomplete_packet -> Fmt.pf ppf "incomplete packet"
      | `Invalid_packet -> Fmt.pf ppf "invalid packet"
      | `Unimplemented_algorithm c -> Fmt.pf ppf "unimplemented algorithm %c" c
      | `Unimplemented_version c -> Fmt.pf ppf "unimplemented version %c" c
      | _ -> Fmt.pf ppf "TODO unimplemented error pp"
    in
    Logs.debug (fun m -> m "Number of packets: %d@.|  %a"
      (List.length packets)
      (Fmt.(list ~sep:(unit "@.|  ") @@ Fmt.vbox ~indent:10 (*TODO figure out how to use Fmt.vbox properly *)
        (pair ~sep:(unit " ") pp_packet_tag
          (pair ~sep:(unit " : ")
             (result ~ok:pp_packet ~error:pp_error) int))))
      (List.map (fun (tag, cs) ->
         tag, (parse_packet_body tag cs, Cs.len cs))
         packets))
  in

  let debug_if_any s = begin function
      | [] -> ()
      | lst ->
        Logs.debug (fun m -> m ("%s: %d") s (List.length lst));
  end
  in

  let () = debug_packets packets in
  (* RFC 4880: - One Public-Key packet: *)
  begin match packets with
    | (Public_key_tag, pub_cs) :: tl -> R.ok (pub_cs, tl)
    | _ -> R.error `Invalid_signature (* TODO more like `Unexpected_packet *)
  end
  >>= fun (root_pub_cs , packets) ->

    (* check that the root public key in the input matches
       the expected public key.
       In GnuPG they check the keyid (64bits of the SHA1). In some cases. Sometimes they don't check at all.
       (gnupg2/g10/sig-check.c:check_key_signature2 if feel like MiTM'ing some package managers)
       We compare the public key MPI data.
       In contrast we don't check the timestamp.
       Pick your poison.
    *)
    Public_key_packet.parse_packet root_pub_cs
    |> R.reword_error (function _ -> `Invalid_packet)
    >>= fun root_pk ->

    (* TODO extract version from the root_pk and make sure the remaining packets use the same version *)

    let find_sig_pair (needle_one:packet_tag_type) (haystack:(packet_tag_type*Cs.t)list) =
    (* finds pairs (needle_one, needle_two) at the head of haystack
       if needle_two is None, it is ignored *)
      list_find_leading_pairs
        (fun (tag1,cs1) -> fun (tag2,cs2) ->
           if tag1 = needle_one && tag2 = Signature_tag
           then R.ok (cs1,cs2)
           else R.error `Invalid_packet
        ) haystack
    in

    let pair_must_be tag = function
      | (t,cs) when t = tag -> Ok (t,cs)
      | _ -> Error `Invalid_packet
    in

    let take_signatures_of_types sig_types (packets:(packet_tag_type*Cs.t)list) =
      packets |> list_take_leading
        (fun (_,cs) ->
           parse_packet cs >>= fun signature ->
           if List.exists (fun t -> t = signature.signature_type) sig_types
           then Ok signature
           else Error `Invalid_packet
        )
    in

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
    let validate_uid_signature (root_pk:Public_key_packet.t) (uid:packet_type) signature =
      (* set up hashing with this signature: *)
      let (hash_cb, hash_final) =
        Signature_packet.digest_callback signature.hash_algorithm
      in
      (* TODO handle version V3 *)
      let () = hash_packet V4 hash_cb (Public_key_packet root_pk) in
      let () = hash_packet V4 hash_cb uid in
      construct_to_be_hashed_cs signature >>| hash_cb >>= fun () ->

      (* Check that the root key has not expired with this UID *)
      public_key_not_expired current_time root_pk signature >>= fun () ->

      check_signature current_time [root_pk] hash_final signature
      |> R.reword_error (function err ->
          Logs.debug (fun m -> m "signature check failed on a uid sig"); err)
    in
    let take_and_validate_certifications packet_tag (validation_callback : Public_key_packet.t -> packet_type -> Signature_packet.t -> ('ok,'error) result) sig_types packets =
       let rec inner_loop (acc : (packet_type * Signature_packet.t list) list) packets =
       let (objects, (packets:(packet_tag_type*Cs.t)list)) =
         list_take_leading (pair_must_be packet_tag) packets |> R.get_ok
        in
      if List.length objects = 0 then
        (* Return from loop: *)
        Ok (List.rev acc , packets)
      else
      (* Drop unsigned objects: *)
      list_drop_e_n `Invalid_packet ((List.length objects)-1) objects
      >>= fun [(object_type, object_cs)] ->
      packets |> take_signatures_of_types sig_types
      >>= fun (certifications, packets) ->
      parse_packet_body object_type object_cs >>= fun obj ->
      (* The certifications can be made by anyone, we are only concerned with the ones made by the root_pk *)
      let valid_certifications =
        certifications |> List.filter
        (fun certification ->
         match validation_callback root_pk obj certification with
         | Ok `Good_signature -> true
         | _ -> false
        )
      in
      if List.length valid_certifications < 1 then begin
        Logs.debug (fun m -> m "Skipping %a due to lack of valid certifications"
                       pp_packet obj
         ) ;
         R.error `Invalid_signature
      end else
         inner_loop ((obj, valid_certifications)::acc) packets
      in inner_loop [] packets
    in
    packets |> take_and_validate_certifications Uid_tag (validate_uid_signature)
        (* We treat these four completely equally: *)
        [ Generic_certification_of_user_id_and_public_key_packet
        ; Persona_certification_of_user_id_and_public_key_packet
        ; Casual_certification_of_user_id_and_public_key_packet
        ; Positive_certification_of_user_id_and_public_key_packet]
    >>= fun (verified_uids , packets) ->
    if List.length verified_uids < 1
    then begin
      Logs.err (fun m -> m "Unable to find at least one verifiable UID.") ;
      R.error `Invalid_packet
    end else R.ok ()
    >>= fun () ->
    let verified_uids =
      verified_uids |> List.map
        (fun (Uid_packet uid,certifications) -> {uid;certifications})
    in

    (* Validate user attributes (basically, embedded image files) *)
    let validate_user_attribute_signature _ _ _ (* root_pk obj signature*) =
            R.error `Not_implemented
    in
    packets |> take_and_validate_certifications User_attribute_tag
      (validate_user_attribute_signature) []
    >>= fun (verified_user_attributes, packets) ->

    (* TODO technically these (pk subpackets) can be followed by revocation signatures; we don't handle that *)
    find_sig_pair Public_subkey_tag packets
    >>= fun subkeys_and_sigs ->
    let subkeys_and_sigs_length = List.length subkeys_and_sigs in
    if subkeys_and_sigs_length > 1000 then begin
      Logs.err (fun m -> m "Encountered more than 1000 subkeys/signatures; this is probably not a legitimate public key") ;
      R.error `Invalid_packet
    end else
    list_drop_e_n `Invalid_packet (subkeys_and_sigs_length*2) packets >>= fun packets ->

    debug_if_any "subkeys_and_sigs" subkeys_and_sigs ;

    let rec check_subkeys_and_sigs acc =
      begin function
        | (subkey_cs,sig_cs)::tl ->
          Public_key_packet.parse_packet subkey_cs
          >>= fun subkey ->
          Signature_packet.parse_packet sig_cs
          >>= fun signature ->
          begin match signature.signature_type with
            | Subkey_binding_signature ->
              R.ok ()
            | _ ->
              Logs.err (fun m -> m "Subkey signature type expected to be %a, actual type is %a"
                           pp_signature_type Subkey_binding_signature
                           pp_signature_type signature.signature_type
                       );
              R.error `Invalid_packet
          end >>= fun () ->

          (* Check that the key has not expired *)
          public_key_not_expired current_time subkey signature >>= fun () ->

          (* RFC 4880: 0x18: Subkey Binding Signature
       This signature is a statement by the top-level signing key that
             indicates that it owns the subkey.*)

          (* set up hashing with this signature: *)
          let (hash_cb, hash_final) =
            Signature_packet.digest_callback signature.hash_algorithm
          in

          (* This signature is calculated directly on the
             primary key and subkey, and not on any User ID or other packets.*)
          Public_key_packet.hash_public_key root_pub_cs hash_cb ;
          Public_key_packet.hash_public_key subkey_cs hash_cb ;

          (* A signature that binds a signing subkey MUST have
       an Embedded Signature subpacket in this binding signature that
       contains a 0x19 signature made by the signing subkey on the
             primary key and subkey: *)

          begin match subkey.Public_key_packet.algorithm_specific_data with
            | Public_key_packet.RSA_pubkey_encrypt_asf _
            | Public_key_packet.Elgamal_pubkey_asf _ ->
              R.ok ()
            | Public_key_packet.RSA_pubkey_sign_asf _
            | Public_key_packet.RSA_pubkey_encrypt_or_sign_asf _
            | Public_key_packet.DSA_pubkey_asf _ ->
           (* 5.2.3.21.  Key Flags
              The flags in this packet may appear in self-signatures or in
              certification signatures.  They mean different things depending on
              who is making the statement -- for example, a certification
              signature that has the "sign data" flag is stating that the
              certification is for that use. *)
              if filter_subpacket_tag Key_flags signature.subpacket_data
                 |> List.for_all (function
                         | ((Some (Key_usage_flags {
                               usage_certify_keys = false;
                               usage_sign_data = false; _ }
                           )),_,_) -> true
                     | _ -> false
                   ) then begin
                Logs.debug (fun m -> m "Accepting subkey binding without embedded signature because the key flags have {usage_certify_keys=false;usage_sign_data=false}");
                R.ok ()
              end else
              (* Subkeys that can be used for signing must accept inclusion by
                 embedding a signature on the root key (made using the subkey)*)
                let rec loop = function
                  | [] ->
                    Logs.err (fun m -> m "no embedded signature subpacket in subkey binding signature [TODO: parse 'Key Flags' properly to preclude keys without the certification bit] ");
                    R.error `Invalid_packet
                  | (_, Embedded_signature, embedded_cs)::_ ->
                    Signature_packet.parse_packet embedded_cs
                    >>= fun embedded_sig ->
                    check_embedded_signature current_time root_pk embedded_sig subkey
                  | _::tl -> loop tl
                in
                loop signature.subpacket_data
                >>= fun `Good_signature -> R.ok ()
          end
          >>= fun () ->

          construct_to_be_hashed_cs signature >>| hash_cb >>= fun () ->
          check_signature current_time [root_pk] hash_final signature
          >>= fun `Good_signature ->
          check_subkeys_and_sigs ({key = subkey; signature;
                                   revocation = None}::acc) tl
        | [] -> R.ok (List.rev acc)
      end
    in
    check_subkeys_and_sigs [] subkeys_and_sigs >>= fun verified_subkeys ->

    (* Final check: *)
    (* TODO if List.length packets <> 0 then begin
      debug_packets packets ;
      R.error `Extraneous_packets_after_signature
    end else *)
       R.ok ({
         root_key = root_pk
       ; revocations = [] (* TODO *)
       ; uids = verified_uids
       ; user_attributes = [] (* TODO *)
       ; subkeys = verified_subkeys
       }, packets)
  (* RFC 4880 5.2.4: Computing Signatures:
When a signature is made over a key, the hash data starts with the
   octet 0x99, followed by a two-octet length of the key, and then body
   of the key packet.  (Note that this is an old-style packet header for
   a key packet with two-octet length.)  A subkey binding signature
   (type 0x18) or primary key binding signature (type 0x19) then hashes
   the subkey using the same format as the main key (also using 0x99 as
   the first octet).  Key revocation signatures (types 0x20 and 0x28)
       hash only the key being revoked. *)
end

let ()= Signature.( () ) (* TODO otherwise emacs complains about unused module*)
