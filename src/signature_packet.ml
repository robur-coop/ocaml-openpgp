open Types
open Rresult

type signature_asf =
  | RSA_sig_asf of { m_pow_d_mod_n : mpi } (* PKCS1-*)
  | DSA_sig_asf of { r: mpi; s: mpi; }

(* [t] and [signature_subpacket] are mutually recursive
   due to Embedded_signature containing [t] *)
type t = {
  (* TODO consider some fancy gadt thing here*)
  signature_type : signature_type ;
  public_key_algorithm : public_key_algorithm ;
  hash_algorithm : hash_algorithm ;
  (* This implementation ignores "unhashed subpacket data",
     so we only store "hashed subpacket data": *)
  subpacket_data : signature_subpacket list ;
  algorithm_specific_data : signature_asf;
}

and signature_subpacket =
  | Signature_creation_time of Ptime.t
  | Signature_expiration_time of Ptime.Span.t
  | Key_expiration_time of Ptime.Span.t
  | Key_usage_flags of key_usage_flags
  | Issuer_fingerprint of openpgp_version * Cs.t
  | Preferred_hash_algorithms of hash_algorithm list
  | Embedded_signature of t
  | Key_server_preferences of Cs.t
  | Issuer_keyid of Cs.t (* key id; rightmost 64-bits of sha1 of pk *)
  | Unimplemented_subpacket of signature_subpacket_tag * Cs.t

let signature_subpacket_tag_of_signature_subpacket packet : signature_subpacket_tag =
  match packet with
  | Signature_creation_time _ -> Signature_creation_time
  | Signature_expiration_time _ -> Signature_expiration_time
  | Key_expiration_time _ -> Key_expiration_time
  | Key_usage_flags _ -> Key_flags
  | Issuer_fingerprint _ -> Issuer_fingerprint
  | Preferred_hash_algorithms _ -> Preferred_hash_algorithms
  | Embedded_signature _ -> Embedded_signature
  | Key_server_preferences _ -> Key_server_preferences
  | Issuer_keyid _ -> Issuer
  | Unimplemented_subpacket (tag,_) -> tag

(* [pp] and [pp_signature_subpacket] are mutually recursive because a [t] can
   contain embedded signatures. *)
let rec pp ppf t =
  Fmt.pf ppf "{ signature type: [%a]@,; public key algorithm: [%a]@,; hash algorithm: [%a]@,; subpackets: @,%a"
    pp_signature_type t.signature_type
    pp_public_key_algorithm t.public_key_algorithm
    pp_hash_algorithm t.hash_algorithm
    Fmt.(brackets @@ hvbox ~indent:2 @@
         list ~sep:(unit "")
           (prefix cut @@ hvbox ~indent:2 @@
              pp_signature_subpacket))
      t.subpacket_data

and pp_signature_subpacket ppf pkt =
  let tag = signature_subpacket_tag_of_signature_subpacket pkt in
  let pp_tag = pp_signature_subpacket_tag in
  () |> Fmt.pf ppf "(%a: %a)" pp_tag tag @@ fun fmt () ->
  begin match pkt with
  | Signature_creation_time time -> Fmt.pf fmt "UTC: %a" Ptime.pp time
  | ( Signature_expiration_time time
    | Key_expiration_time time) -> Fmt.pf fmt "%a" Ptime.Span.pp time
  | Key_usage_flags (* TODO also prettyprint unimplemented flags *)
    { certify_keys = certs
    ; sign_data = sign_data
    ; encrypt_communications = enc_comm
    ; encrypt_storage = enc_store
    ; authentication = auth
    ; unimplemented = unimpl_char }
    -> Fmt.pf fmt "{ @[<v>certify: %b ;@ sign data: %b ;@ encrypt communications: %b ;@ encrypt storage: %b ;@ authentication: %b ;@ raw decimal char: %C@]}" certs sign_data enc_comm enc_store auth unimpl_char
  | Issuer_fingerprint (v,fp) -> begin match v with
      | V3 (*TODO is this valid for V3? *)
      | V4 -> Fmt.pf fmt "SHA1: %s" (Cs.to_hex fp)
    end
  | Preferred_hash_algorithms algos ->
    Fmt.pf fmt "%a"
      Fmt.(brackets @@ hvbox ~indent:2 @@
           list ~sep:(unit "; ") pp_hash_algorithm) algos
  | Embedded_signature em_sig -> Fmt.pf fmt "@[%a@]" pp em_sig
  | Key_server_preferences cs -> Fmt.pf fmt "%a" Cstruct.hexdump_pp cs
  | Issuer_keyid cs -> Fmt.pf fmt "%a" Cstruct.hexdump_pp cs
  | Unimplemented_subpacket (_, cs) -> Fmt.pf fmt "%a" Cstruct.hexdump_pp cs
  end

let filter_subpacket_tag (tag:signature_subpacket_tag) =
  List.filter
    (fun subpkt -> tag = signature_subpacket_tag_of_signature_subpacket subpkt)

let public_key_not_expired (current_time : Ptime.t)
    {Public_key_packet.timestamp;_} (t:t) =
  (* Verify that the creation timestamp of
     [pk] plus the [t].Key_expiration_time is ahead of [current_time] *)
  match filter_subpacket_tag Key_expiration_time t.subpacket_data with
  | [Key_expiration_time expiry] ->
    e_log_ptime_plus_span_is_smaller
      (fun m -> m "public_key_not_expired: EXPIRED: %a > %a from %a"
                     Ptime.pp current_time
                     Ptime.Span.pp expiry Ptime.pp timestamp)
      (timestamp,expiry) current_time >>| fun () ->
    Logs.debug (fun m -> m "public_key_not_expired: Good: %a < %a from %a"
                 Ptime.pp current_time
                 Ptime.Span.pp expiry Ptime.pp timestamp )
  | [] ->
    Logs.debug (fun m -> m "public_key_not_expired: No expiration timestamp") ;
    Ok ()
  | _ -> error_msg (fun m -> m "Multiple expiration timestamps found in sig TODO")

let signature_expiration_date_is_valid (current_time : Ptime.t) (t : t) =
    (* must have a Signature_creation_time to be valid: *)
    match filter_subpacket_tag Signature_creation_time t.subpacket_data with
    | [] -> error_msg (fun m -> m "Missing signature creation time")
    | [Signature_creation_time base] ->
        begin match filter_subpacket_tag Signature_expiration_time t.subpacket_data with
        | [] -> Ok ()
        | [Signature_expiration_time expiry] ->
          e_log_ptime_plus_span_is_smaller
            (fun m -> m "Bad time: %a > %a + %a"
               Ptime.pp current_time Ptime.Span.pp expiry Ptime.pp base )
            (base,expiry) current_time >>| fun () ->
              Logs.debug (fun m -> m "Good time: %a < %a + %a"
                    Ptime.pp current_time Ptime.Span.pp expiry Ptime.pp base )
        | _ ->
          error_msg (fun m -> m "Multiple signature expiration times")
        end
    | _ ->
      error_msg (fun m -> m "Multiple signature creation times")

let check_signature (current_time : Ptime.t)
    (public_keys : Public_key_packet.t list)
    digest_finalizer
    t
  : ('ok, [> `Msg of string]) result =
  (* Note that this function does not deal with key expiry.
   * if you are checking the signature of a subkey,
   * you must take care to verify that expiry date is within current_time
   * using the function called "public_key_not_expired".
  *)
  (* TODO check backsig, see g10/sig-check.c:signature_check2 *)
  (* TODO
   Bit 7 of the subpacket type is the "critical" bit.  If set, it
   denotes that the subpacket is one that is critical for the evaluator
   of the signature to recognize.  If a subpacket is encountered that is
   marked critical but is unknown to the evaluating software, the
   evaluator SHOULD consider the signature to be in error.
  *)
  let digest = digest_finalizer () in
  let rec loop (pks : Public_key_packet.t list) =
    match pks with
    | [] -> Error `Invalid_signature
    | pk::remaining_keys when t.subpacket_data |> List.exists (function
        (* Skip pk that has fp <> SHA1 from t.Issuer_fingerprint *)
        | Issuer_fingerprint (V4,fp) when
            not @@ Cs.equal fp pk.Public_key_packet.v4_fingerprint -> true
        (* | Issuer keyid when TODO check for 64-bit keyid also? *)
        | _ -> false
      ) -> loop remaining_keys
    | pk::remaining_keys ->
    let res =
    signature_expiration_date_is_valid current_time t
    >>= fun () ->
    (begin match pk.Public_key_packet.algorithm_specific_data ,
                t.algorithm_specific_data with
    | Public_key_packet.DSA_pubkey_asf key, DSA_sig_asf {r;s;} ->
      Logs.debug (fun m -> m "Trying to verify a DSA signature") ;
      dsa_asf_are_valid_parameters ~p:key.Nocrypto.Dsa.p
                                   ~q:key.Nocrypto.Dsa.q
                                   ~hash_algo:t.hash_algorithm
      >>= fun () ->
      let cs_r = cs_of_mpi_no_header r in
      let cs_s = cs_of_mpi_no_header s in
      e_true `Invalid_signature
        (Nocrypto.Dsa.verify ~key (cs_r,cs_s) digest)
      |> log_failed (fun m -> m "DSA signature validation failed")
      >>| fun () -> `Good_signature
    | ( Public_key_packet.RSA_pubkey_sign_asf pub
      | Public_key_packet.RSA_pubkey_encrypt_or_sign_asf pub), RSA_sig_asf {m_pow_d_mod_n} ->
        (* TODO validate parameters? *)
        let()= Logs.debug (fun m ->
            m "Trying to verify computed digest\n%s\n against an RSA signature %s"
              (Cs.to_hex digest)
              (Cs.to_hex (cs_of_mpi_no_header m_pow_d_mod_n)))
        in
        let module PKCS : Nocrypto.Rsa.PKCS1.S =
              (val (nocrypto_pkcs_module_of_hash_algorithm t.hash_algorithm)) in
        e_true `Invalid_signature
          (PKCS.verify_cs ~key:pub ~digest (cs_of_mpi_no_header m_pow_d_mod_n))
        |> log_failed (fun m -> m "RSA signature validation failed")
        >>| fun () -> `Good_signature
    | _ , _ ->
      error_msg
        (fun m -> m "Not implemented: Validating signatures with this pk type")
    end)
    in
    begin match res with
    | Error `Invalid_signature ->
      let() = Logs.debug (fun m -> m "Failed to verify signature, trying next key (if any)") in
      loop remaining_keys
    | Ok _ -> (res |> log_msg (fun m -> m "Got a good signature!"))
    | e -> log_failed (fun m -> m "Couldn't verify sig for some reason") e
    end
  in
  loop public_keys |> R.reword_error (function
      | `Invalid_signature -> `Msg "Failed to verify signature"
      | (`Msg _) as m -> m)

let serialize_asf = function
  | RSA_sig_asf v -> cs_of_mpi v.m_pow_d_mod_n
  | DSA_sig_asf v -> cs_of_mpi_list [v.r; v.s]

(* the serialization functions are mutually recursive in order to
   support Embedded_signature *)

let rec serialize_signature_subpackets subpackets : (Cs.t,[>]) result =
  subpackets |> result_ok_list_or_error
    (fun subpkt ->
       cs_of_signature_subpacket subpkt >>= fun cs ->
       Cs.concat [ serialize_packet_length_int (Cs.len cs)
                 ; cs ] |> R.ok
    )
  >>| Cs.concat

and serialize_hashed_manual version sig_type pk_algo hash_algo subpacket_data =
  (* Serialize the hashed parts of a signature packet *)
  (* TODO add error handling here:*)
  serialize_signature_subpackets subpacket_data >>= fun serialized_subpackets ->
  let subpackets_len = Cs.len serialized_subpackets in

  ((true_or_error (subpackets_len < 0xffff))
   (fun m -> m "TODO better error, but failing because subpackets are longer than it's possible to sign (0xFF_FF < %d: %s)"
        (subpackets_len)
        (Cs.to_hex serialized_subpackets)))
  >>| fun () ->
  (* A V4 signature hashes the packet body
   starting from its first field, the version number, through the end
   of the hashed subpacket data.  Thus, the fields hashed are the
   signature version, the signature type, the public-key algorithm, the
   hash algorithm, the hashed subpacket length, and the hashed
   subpacket body.
  *)
  let buf = Cs.W.create (4 + 2 + subpackets_len) in
  Cs.W.char buf (char_of_version version) ;
  Cs.W.char buf (char_of_signature_type sig_type) ;
  Cs.W.char buf (char_of_public_key_algorithm pk_algo) ;

  (* Can't infer this from the algo-specific data type because
     RSA_sign_only vs RSA_encrypt_or_sign generate different bytes here.*)
  Cs.W.char buf (char_of_hash_algorithm hash_algo) ;

  (* len of hashed subpacket data: *)
  Cs.W.cs buf (Cs.BE.create_uint16 subpackets_len) ;

  (* subpacket data: *)
  Cs.W.cs buf serialized_subpackets ;
  Cs.W.to_cs buf

and serialize_hashed version {signature_type ; public_key_algorithm
                                 ; hash_algorithm ; subpacket_data;_ } =
  serialize_hashed_manual version signature_type
    public_key_algorithm hash_algorithm subpacket_data

and construct_to_be_hashed_cs_manual version sig_type pk_algo hash_algo
    subpacket_data =
  (* TODO handle V3 *)
  Logs.debug (fun m -> m "%s" __LOC__);
  serialize_hashed_manual version sig_type pk_algo hash_algo subpacket_data
  >>| (fun buf ->
  (* V4 signatures also hash in a final trailer of six octets: the
   version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
   big-endian number that is the length of the hashed data from the
   Signature packet (note that this number does not include these final
            six octets).*)
  Cs.concat [ buf
            ; Cs.BE.create_uint16 0x04_ff
            ; Cs.BE.create_uint32 (Cs.len buf |> Int32.of_int) ]
   ) >>= fun tbh -> (Ok tbh) |>
  log_msg (fun m -> m "signature to be hashed: @ %a" Cstruct.hexdump_pp tbh)

and construct_to_be_hashed_cs t : ('ok,'error) result =
  (* This is a helper function to be used on [t]s for verification purposes *)
  construct_to_be_hashed_cs_manual V4 t.signature_type
    t.public_key_algorithm t.hash_algorithm
    t.subpacket_data

and cs_of_signature_subpacket pkt =
  begin match pkt with
  | Signature_creation_time time ->
    Cs.BE.e_create_ptime32 (`Msg "invalid sig creation time") time
  | ( Signature_expiration_time time
    | Key_expiration_time time) ->
    Cs.BE.e_create_ptimespan32 (`Msg "invalid expiry time") time
  | Key_usage_flags flags -> Ok (cs_of_key_usage_flags flags)
  | Issuer_fingerprint (v,fp) -> Ok (Cs.concat [cs_of_version v;fp])
  | Preferred_hash_algorithms algos ->
    Ok (Cs.concat @@ List.map cs_of_hash_algorithm algos)
  | Embedded_signature embedded -> serialize embedded
  | Issuer_keyid cs
  | Key_server_preferences cs
  | Unimplemented_subpacket (_ , cs) -> Ok cs (* cs does not contain the tag *)
  end
  |> log_failed (fun m -> m "Error while serializing signature subpacket: %a"
                    pp_signature_subpacket pkt)
  >>| fun cs ->
  (* TODO need to implement the "critical bit" (leftmost bit=1) on subpacket tag types here if they are critical.*)
  Cs.concat [ signature_subpacket_tag_of_signature_subpacket pkt
              |> cs_of_signature_subpacket_tag
            ; cs]
  |> log_msg (fun m -> m "serialized subpacket: @[%a@ %a@]"
                pp_signature_subpacket pkt Cstruct.hexdump_pp cs)


and serialize t =
  (* TODO handle V3 *)
  serialize_hashed V4 t >>= fun hashed ->
  compute_digest t.hash_algorithm hashed >>| (fun digest -> Cs.sub digest 0 2)
  >>= fun two_octet_checksum ->
  serialize_asf t.algorithm_specific_data >>| fun asf_cs ->
  Cs.concat [ hashed
              (* length of unhashed subpackets (which we don't support): *)
            ; Cs.BE.create_uint16 0
              (* leftmost 16 bits of the signed hash value: *)
            ; two_octet_checksum
            ; asf_cs ]

let hash t hash_cb = construct_to_be_hashed_cs t >>| hash_cb

let parse_subpacket ~allow_embedded_signatures buf
  : (signature_subpacket, [> `Msg of string]) result =
  Cs.e_split (`Msg "parse_subpacket: e_split") buf 1 >>= fun (tag, data) ->
  let tag_c, is_critical =
    let tag_i = Cstruct.get_uint8 tag 0 in
    Char.chr (tag_i land 0x7f), (tag_i land 0x80 = 0x80)
    (* RFC 4880: 5.2.3.1.  Signature Subpacket Specification
       Bit 7 of the subpacket type is the "critical" bit.  If set, it
       denotes that the subpacket is one that is critical for the evaluator
       of the signature to recognize.  If a subpacket is encountered that is
       marked critical but is unknown to the evaluating software, the
       evaluator SHOULD consider the signature to be in error.
    *)
  in
  let tag = signature_subpacket_tag_of_char tag_c in
  Logs.debug (fun m -> m "parse_subpacket: going to parse: [%a] %s"
    pp_signature_subpacket_tag tag
    (Cs.to_hex data)
  ) ;
  begin match tag with
  | Key_flags when Cs.len data = 1 ->
      Ok (Some (
        Key_usage_flags (key_usage_flags_of_char @@ Cstruct.get_char data 0)))
  (* Parse timestamps. Note that OpenPGP stores the expiration as an offset from
   * the creation time. *)
  | Signature_creation_time ->
    Cs.BE.e_get_ptime32 (`Msg "can't read signature creation time") data 0
    >>| fun ptime -> Some (Signature_creation_time ptime)
  | Signature_expiration_time ->
    Cs.BE.e_get_ptimespan32 (`Msg "can't read signature expiry time") data 0
    >>| fun pspan -> Some (Signature_expiration_time pspan)
  | Key_expiration_time ->
    Cs.BE.e_get_ptimespan32 (`Msg "can't read key expiry time") data 0
    >>| fun pspan -> Some (Key_expiration_time pspan)
  | Issuer_fingerprint ->
    Cs.e_get_char (`Msg "issuer fp") data 0
    >>= e_version_of_char (`Msg "version of char TODO")
      >>= begin function
        | V4 when Cs.len data = 1 + Nocrypto.Hash.SHA1.digest_size ->
          Ok (Some (Issuer_fingerprint (V4,
                      Cs.(sub data 1 Nocrypto.Hash.SHA1.digest_size))))
        | V3 (*TODO don't think Issuer_fingerprint was a thing in V3? *)
        | V4 -> error_msg (fun m -> m "Invalid issuer fingerprint packet: %a"
                              Cstruct.hexdump_pp data)
      end
  | Preferred_hash_algorithms ->
    Cs.to_list data |> result_ok_list_or_error hash_algorithm_of_char
      >>| fun lst -> Some (Preferred_hash_algorithms lst)
  | Embedded_signature when not allow_embedded_signatures ->
      error_msg (fun m -> m "Embedded signatures not allowed in this context")
  | _ when not is_critical -> Ok None
  | tag -> error_msg (fun m -> m "Unimplemented critical subpacket: [%a] %s"
                         pp_signature_subpacket_tag tag
                         (Cs.to_hex data) )
  end
  >>| function
      | Some parsed_opt ->
          Logs.debug (fun m -> m "Parsed subpacket: %a"
                       pp_signature_subpacket parsed_opt ) ;
          parsed_opt
      | None ->
          Logs.debug (fun m -> m "Uncritical unimplemented subpacket: %a: %s"
                         pp_signature_subpacket_tag tag
                         (Cs.to_hex data) ) ;
          Unimplemented_subpacket (tag,data)

let parse_subpacket_data ~allow_embedded_signatures buf
  : (signature_subpacket list, [> `Msg of string ]) result =
  let rec loop (packets: signature_subpacket list) buf =
    if 0 = Cs.len buf then R.ok (List.rev packets) else
    consume_packet_length None buf >>= fun (pkt, extra) ->
    parse_subpacket ~allow_embedded_signatures pkt
    >>| (fun tuple -> tuple::packets)
    >>= fun packets -> loop packets extra
  in
  loop [] buf

let parse_packet ?(allow_embedded_signatures=false) buf : (t, 'error) result =
  (* 0: 1: '\x04' *)
  v4_verify_version buf >>= fun()->

  (* 1: 1: signature type *)
  signature_type_of_cs_offset buf 1
  >>= fun signature_type ->

  (* 2: 1: public-key algorithm *)
  public_key_algorithm_of_cs_offset buf 2
  >>= fun pk_algo ->

  (* 3: 1: hash algorithm *)
  hash_algorithm_of_cs_offset buf 3
  >>= fun hash_algo ->

  (* 4: 2: length of hashed subpacket data *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf 4
  >>= fun hashed_len ->

  (* 6: hashed_len: hashed subpacket data *)
  Cs.e_sub `Incomplete_packet buf 6 hashed_len
  >>= fun hashed_subpacket_data ->

  parse_subpacket_data ~allow_embedded_signatures hashed_subpacket_data
  >>= fun subpacket_data ->

  (* 6+hashed_len: 2: length of unhashed subpacket data *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf (6+hashed_len)
  >>= fun unhashed_len ->

  (* 6+hashed_len+2: unhashed subpacket data *)
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2) unhashed_len
  >>= fun unhashed_subpacket_data ->
  (* TODO decide what to do with unhashed subpacket data*)
  Logs.debug (fun m -> m "Signature contains unhashed subpacket data (not handled in this implementation: %a" Cstruct.hexdump_pp unhashed_subpacket_data);

  (* 6+hashed_len+2+unhashed_len: 2: leftmost 16 bits of the signed hash value (what the fuck) *)
  (* TODO currently ignored:
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2+unhashed_len) 2
  >>= fun two_byte_checksum ->
  *)

  let asf_offset = 6+hashed_len +2 + unhashed_len + 2 in
  Cs.e_sub `Incomplete_packet buf asf_offset ((Cs.len buf) -asf_offset)
  >>= fun asf_cs ->

  (* public-key algorithm-specific data (ASF):
   * one or more MPI integers with the signature
  *)

  begin match pk_algo with
    | RSA_sign_only
    | RSA_encrypt_or_sign ->
      consume_mpi asf_cs
      >>| fun (m_pow_d_mod_n, asf_tl) -> RSA_sig_asf { m_pow_d_mod_n } , asf_tl
    | DSA ->
      consume_mpi asf_cs >>= fun (r , r_tl_cs) ->
      consume_mpi r_tl_cs >>| fun (s , asf_tl) -> DSA_sig_asf {r ; s} , asf_tl
    | Elgamal_encrypt_only
    | RSA_encrypt_only ->
      error_msg (fun m -> m "TODO signature algorithm uses an encrypt-only key")
   end
  >>= fun (algorithm_specific_data, should_be_empty) ->
  true_or_error (Cs.len should_be_empty = 0)
    (fun m -> m "checking 'should be empty' - still contains %d bytes: %a"
        (Cs.len should_be_empty) Cstruct.hexdump_pp should_be_empty)
  >>| fun () ->
  { signature_type
  ; public_key_algorithm = pk_algo
  ; hash_algorithm = hash_algo
  ; subpacket_data
  ; algorithm_specific_data }
