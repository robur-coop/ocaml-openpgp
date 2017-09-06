open Types
open Rresult

type digest_finalizer = unit -> Cs.t
type digest_feeder =
  (Cstruct.t -> unit) * digest_finalizer

type signature_asf =
  | RSA_sig_asf of { m_pow_d_mod_n : mpi } (* PKCS1-*)
  | DSA_sig_asf of { r: mpi; s: mpi; }

type t = {
  (* TODO consider some fancy gadt thing here*)
  signature_type : signature_type ;
  public_key_algorithm : public_key_algorithm ;
  hash_algorithm : hash_algorithm ;
  (* This implementation ignores "unhashed subpacket data",
     so we only store "hashed subpacket data": *)
  subpacket_data : (signature_subpacket option * signature_subpacket_tag * Cs.t) list ;
  algorithm_specific_data : signature_asf;
}

let pp ppf t =
  let resultify : 'a -> (signature_subpacket,signature_subpacket_tag)result
    = function
    | Some a,_,_ -> Ok a
    | _, b, _ -> Error b
  in
  Fmt.pf ppf "{ signature type: [%a]@,; public key algorithm: [%a]@,; hash algorithm: [%a]@,; subpackets: @,%a"
    pp_signature_type t.signature_type
    pp_public_key_algorithm t.public_key_algorithm
    pp_hash_algorithm t.hash_algorithm
    Fmt.(brackets @@ hvbox ~indent:2 @@
         list ~sep:(unit "")
           (prefix cut @@ hvbox ~indent:2 @@
            result ~ok:pp_signature_subpacket
                   ~error:pp_signature_subpacket_tag))
    (List.map resultify t.subpacket_data)

let digest_callback hash_algo: digest_feeder =
  let module H = (val (nocrypto_module_of_hash_algorithm hash_algo)) in
  let t = H.init () in
  let feeder cs =
    Logs.debug (fun m -> m "hashing %d: %s\n" (Cs.len cs) (Cs.to_hex cs)) ;
    H.feed t cs
  in
  (feeder, (fun () -> H.get t))

let compute_digest hash_algo to_be_hashed =
  let (feed , get) = digest_callback hash_algo in
  let () = feed to_be_hashed in
  R.ok (get ())

let serialize_signature_subpackets subpackets : Cs.t =
  subpackets |> List.map
    (fun (parsed,tag,subpkt) ->
       Logs.debug (fun m -> m "serializing subpacket of len %d:@,%a @,%a"
                      (Cs.len subpkt) Fmt.(option pp_signature_subpacket) parsed
                      Cstruct.hexdump_pp subpkt
       ) ;

       (* TODO need to implement the "critical bit" (leftmost bit=1) on subpacket tag types here if they are critical.*)

       Cs.concat [serialize_packet_length_int (1 + Cs.len subpkt)
                 (* ^-- 1 byte for the tag *)
                 ; cs_of_signature_subpacket_tag tag; subpkt]
    )
  |> Cs.concat

let filter_subpacket_tag (tag:signature_subpacket_tag) =
  List.filter
    (function
     | Some _, htag, _ -> tag = htag (* TODO verify the Some matches tag ?*)
     | _, _, _ -> false)

let public_key_not_expired (current_time : Ptime.t)
    {Public_key_packet.timestamp;_} (t:t) =
  (* Verify that the creation timestamp of
     [pk] plus the [t].Key_expiration_time is ahead of [current_time] *)
  match filter_subpacket_tag Key_expiration_time t.subpacket_data with
  | [(Some (Key_expiration_time expiry)), Key_expiration_time, _] ->
    e_compare_ptime_plus_span `Invalid_signature (*TODO better error msg *)
      (timestamp,expiry) current_time
    >>= begin function
      | 1 ->
        Logs.debug (fun m -> m "public_key_not_expired: Good: %a < %a from %a"
                       Ptime.pp current_time
                       Ptime.Span.pp expiry Ptime.pp timestamp
                   ) ;
        Ok ()
      | _ ->
        Logs.err (fun m -> m "public_key_not_expired: EXPIRED: %a > %a from %a"
                     Ptime.pp current_time
                     Ptime.Span.pp expiry Ptime.pp timestamp
        ) ;
        Error `Invalid_signature
    end
  | [] ->
    Logs.debug (fun m -> m "public_key_not_expired: No expiration timestamp") ;
    Ok ()
  | _ -> Logs.err (fun m -> m "Multiple expiration timestamps found in sig TODO") ;
    Error `Invalid_signature

let signature_expiration_date_is_valid (current_time : Ptime.t) (t : t) =
    (* must have a Signature_creation_time to be valid: *)
    match filter_subpacket_tag Signature_creation_time t.subpacket_data with
    | [] ->
      Logs.err (fun m -> m "Missing signature creation time") ;
      Error `Invalid_signature
    | [(Some (Signature_creation_time base)),_,_] ->
        begin match filter_subpacket_tag Signature_expiration_time t.subpacket_data with
        | [] -> Ok ()
        | [(Some (Signature_expiration_time expiry)),_,_] ->
          begin match e_compare_ptime_plus_span `Invalid_signature
                        (base,expiry) current_time with
            | Ok 1 ->
              Logs.debug (fun m -> m "Good time: %a < %a + %a"
                    Ptime.pp current_time Ptime.Span.pp expiry Ptime.pp base ) ;
              Ok ()
            | _ -> (* If it's expired, or base+expiry is not valid *)
              Logs.err (fun m -> m "Bad time: %a > %a + %a"
                    Ptime.pp current_time Ptime.Span.pp expiry Ptime.pp base ) ;
              Error `Invalid_signature
            end
        | _ ->
          Logs.err (fun m -> m "Multiple signature expiration times") ;
          Error `Invalid_signature (* TODO shouldn't have to check for this *)
        end
    | _ ->
      Logs.err (fun m -> m "Multiple signature creation times") ;
      Error `Invalid_signature

let check_signature (current_time : Ptime.t)
    (public_keys : Public_key_packet.t list)
    digest_finalizer
    t
  : ('ok, 'err) result =
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
        | Some (Issuer_fingerprint (V4,fp)), _, _ when
            not @@ Cs.equal fp pk.Public_key_packet.v4_fingerprint -> true
        (* | Some (Issuer keyid), _, _ when TODO check for 64-bit keyid also? *)
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
      begin match Nocrypto.Dsa.verify ~key (cs_r,cs_s) digest with
        | true -> R.ok `Good_signature
        | false -> R.error `Invalid_signature
      end
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
      begin match PKCS.verify_cs ~key:pub ~digest (cs_of_mpi_no_header m_pow_d_mod_n) with
      | true -> R.ok `Good_signature
      | false ->
        Logs.debug (fun m -> m "RSA signature validation failed") ;
        R.error `Invalid_signature
      end
    | _ , _ ->
      Logs.debug (fun m -> m "Not implemented: Validating signatures with this pk type") ;
      R.error (`Unimplemented_algorithm '=') (* TODO clarify error message *)
    end)
    in
    if res = Error `Invalid_signature then begin
      let() = Logs.debug (fun m -> m "Failed to verify signature, trying next key (if any)") in
      loop remaining_keys
    end else (Logs.debug (fun m -> m "Got a good signature!"); res)
  in
  loop public_keys

let construct_to_be_hashed_cs t : ('ok,'error) result =
  let buf = Buffer.create 10 in
  let char = Buffer.add_char buf in
  let ichar = fun i -> Char.chr i |> char in
  (* A V4 signature hashes the packet body
   starting from its first field, the version number, through the end
   of the hashed subpacket data.  Thus, the fields hashed are the
   signature version, the signature type, the public-key algorithm, the
   hash algorithm, the hashed subpacket length, and the hashed
   subpacket body.
  *)
  (* version: *)
  char '\x04' ;(*TODO don't hardcode version*)

  char (char_of_signature_type t.signature_type) ;

  char (char_of_public_key_algorithm t.public_key_algorithm) ;
  (* Can't infer this from the algo-specific data type because
     RSA_sign_only vs RSA_encrypt_or_sign generate different bytes here.*)

  char (char_of_hash_algorithm t.hash_algorithm) ;

  (* TODO add error handling here:*)
  let serialized_subpackets = serialize_signature_subpackets t.subpacket_data
                            |> Cs.to_string in

  if String.length serialized_subpackets > 0xffff then begin
    Logs.debug (fun m ->
      m "TODO better error, but failing because subpackets are longer than it's possible to sign (0xFF_FF < %d)"
      (String.length serialized_subpackets)
    ) ;
    R.error `Invalid_packet
  end else R.ok ()
  >>= fun () ->

  (* len of hashed subpacket data: *)
  ichar ((String.length serialized_subpackets lsr 8) land 0xff) ;
  ichar ((String.length serialized_subpackets) land 0xff) ;

  (* subpacket data: *)
  Buffer.add_string buf serialized_subpackets ;

  (* V4 signatures also hash in a final trailer of six octets: the
   version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
   big-endian number that is the length of the hashed data from the
   Signature packet (note that this number does not include these final
            six octets).*)
  let() =
    let hashed_so_far_count = Buffer.length buf |> Int32.of_int in
    ichar 0x04 ;
    ichar 0xff ;
    let len = Cstruct.create 4 in
    Cstruct.BE.set_uint32 len 0 hashed_so_far_count ;
    Buffer.add_string buf (Cs.to_string len)
  in
  R.ok (Buffer.contents buf|>Cstruct.of_string)

let parse_subpacket buf : (signature_subpacket option * signature_subpacket_tag * Cs.t, [> `Invalid_packet]) result =
  (* TODO this function should return the parsed data also, but need to write more parsers and add a type for that *)
  Cs.e_split `Invalid_packet buf 1 >>= fun (tag, data) ->
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
      Ok ( Some (
        Key_usage_flags (key_usage_flags_of_char @@ Cstruct.get_char data 0)))
  (* Parse timestamps. Note that OpenPGP stores the expiration as an offset from
   * the creation time. *)
  | Signature_creation_time ->
      Cs.BE.e_get_ptime32 `Invalid_packet data 0 >>= fun ptime ->
      Some (Signature_creation_time ptime) |> R.ok
  | Signature_expiration_time ->
      Cs.BE.e_get_ptimespan32 `Invalid_packet data 0 >>= fun pspan ->
      Some (Signature_expiration_time pspan) |> R.ok
  | Key_expiration_time ->
      Cs.BE.e_get_ptimespan32 `Invalid_packet data 0 >>= fun pspan ->
      Some (Key_expiration_time pspan) |> R.ok
  | Issuer_fingerprint ->
      Cs.e_get_char `Invalid_packet data 0 >>= e_version_of_char `Invalid_packet
      >>= begin function
        | V4 when Cs.len data = 1 + Nocrypto.Hash.SHA1.digest_size ->
          Ok (Some (Issuer_fingerprint (V4,
                      Cs.(sub data 1 Nocrypto.Hash.SHA1.digest_size))))
        | V3 (*TODO don't think Issuer_fingerprint was a thing in V3? *)
        | V4 -> Error `Invalid_packet
      end
  | Preferred_hash_algorithms ->
    Cs.to_list data |> result_ok_list_or_error hash_algorithm_of_char
      >>= fun lst -> Ok (Some (Preferred_hash_algorithms lst))
  | _ when not is_critical -> Ok None
  | tag ->
      Logs.err (fun m -> m "Unimplemented critical subpacket: [%a] %s"
        pp_signature_subpacket_tag tag
        (Cs.to_hex data)
      ) ;
      R.error (`Unimplemented_algorithm tag_c)
  end
  >>| function
      | Some parsed_opt ->
          Logs.debug (fun m -> m "Parsed subpacket: %a"
            pp_signature_subpacket parsed_opt ) ;
          (Some parsed_opt, tag, data)
      | None ->
          Logs.debug (fun m -> m "Uncritical unimplemented subpacket: %a: %s"
            pp_signature_subpacket_tag tag
            (Cs.to_hex data) ) ;
          (None, tag, data)

let parse_subpacket_data buf
  : ((signature_subpacket option * signature_subpacket_tag *Cs.t)list,
     [>`Invalid_packet | `Unimplemented_algorithm of char ]) result =
  let rec loop (packets:(signature_subpacket option * signature_subpacket_tag*Cs.t)list) buf =
    consume_packet_length None buf
    >>= fun (pkt, extra) ->
    parse_subpacket pkt >>| (fun tuple -> tuple::packets)
    >>= fun packets ->
    if Cs.len extra = 0 then
      R.ok (List.rev packets)
    else
      loop packets extra
  in
  (loop [] buf
   |>
   R.reword_error (begin function
        (* partial lengths are not allowed in signature subpackets: *)
       | (`Unimplemented_algorithm _) as e -> e
       | _ -> `Invalid_packet end
      :> 'a -> [>`Invalid_packet|`Unimplemented_algorithm of char]
     )
  )

let parse_packet buf : (t, 'error) result =
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

  parse_subpacket_data hashed_subpacket_data
  >>= fun subpacket_data ->

  (* 6+hashed_len: 2: length of unhashed subpacket data *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf (6+hashed_len)
  >>= fun unhashed_len ->

  (* 6+hashed_len+2: unhashed subpacket data *)
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2) unhashed_len
  >>= fun unhashed_subpacket_data ->
  (* TODO decide what to do with unhashed subpacket data*)
  Logs.debug (fun m -> m "Signature contains unhashed subpacket data (not handled in this implementation: %s" (Cs.to_hex unhashed_subpacket_data));

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
      >>= fun (m_pow_d_mod_n, asf_tl) ->
       R.ok (RSA_sig_asf { m_pow_d_mod_n } , asf_tl)
    | DSA ->
      consume_mpi asf_cs >>= fun (r , r_tl_cs) ->
      consume_mpi r_tl_cs >>= fun (s , asf_tl) ->
      R.ok (DSA_sig_asf {r ; s} , asf_tl)
    | Elgamal_encrypt_only
    | RSA_encrypt_only ->
      Logs.debug (fun m -> m "TODO signature algorithm uses an encrypt-only key");
      R.error `Invalid_packet
   end
  >>= fun (algorithm_specific_data, should_be_empty) ->
  if Cs.len should_be_empty <> 0 then begin
    Logs.debug (fun m -> m "checking 'should be empty' - still contains %d bytes: " (Cs.len should_be_empty)) ;

    R.error `Invalid_packet
  end else
    R.ok {
          signature_type ;
          public_key_algorithm = pk_algo;
          hash_algorithm = hash_algo;
          subpacket_data ;
          algorithm_specific_data
         }
