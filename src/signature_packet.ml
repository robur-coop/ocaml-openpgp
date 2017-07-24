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
  (* note: pk algo type is inferred from asf variant *)
  (* public_key_algorithm : public_key_algorithm ; *)
  hash_algorithm : hash_algorithm ;
  (* This implementation ignores "unhashed subpacket data",
     so we only store "hashed subpacket data": *)
  subpacket_data : (signature_subpacket_tag * Cs.t) list ;
  algorithm_specific_data : signature_asf;
}

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
    (fun (_,subpkt) ->
       Logs.debug (fun m -> m "serializing subpackets of len %d: %s"
                      (Cs.len subpkt) (Cs.to_hex subpkt));

       (* TODO need to implement the "critical bit" (leftmost bit=1) on subpacket tag types here if they are critical.*)

       Cs.concat [serialize_packet_length subpkt; subpkt]
    )
  |> Cs.concat


let check_signature (public_key:Public_key_packet.t)
    hash_algo
    digest_finalizer
    t  : ('ok, 'err) result =
  (* TODO handle expiry date *)
  (* TODO check backsig, see g10/sig-check.c:signature_check2 *)
  (* TODO
   Bit 7 of the subpacket type is the "critical" bit.  If set, it
   denotes that the subpacket is one that is critical for the evaluator
   of the signature to recognize.  If a subpacket is encountered that is
   marked critical but is unknown to the evaluating software, the
   evaluator SHOULD consider the signature to be in error.
  *)
  let digest = digest_finalizer () in
  begin match public_key.Public_key_packet.algorithm_specific_data ,
              t.algorithm_specific_data with
  | Public_key_packet.DSA_pubkey_asf key, DSA_sig_asf {r;s;} ->
    dsa_asf_are_valid_parameters ~p:key.Nocrypto.Dsa.p ~q:key.Nocrypto.Dsa.q ~hash_algo
    >>= fun () ->
    let cs_r = cs_of_mpi_no_header r in
    let cs_s = cs_of_mpi_no_header s in
    begin match Nocrypto.Dsa.verify ~key (cs_r,cs_s) digest with
      | true -> R.ok `Good_signature
      | false -> R.error `Invalid_signature
    end
  | _ , _ -> R.error (`Unimplemented_algorithm '=')
  end

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

  char (char_of_public_key_algorithm
          begin match t.algorithm_specific_data with
            | RSA_sig_asf _ -> RSA_sign_only
            (* TODO this is not correct;
               TODO it doesn't allow for RSA_encrypt_or_sign*)
            | DSA_sig_asf _ -> DSA
          end
       ) ;

  char (char_of_hash_algorithm t.hash_algorithm) ;

  (* TODO add error handling here:*)
  let serialized_subpackets = serialize_signature_subpackets t.subpacket_data
                            |> Cs.to_string in

  if String.length serialized_subpackets > 0xffff then begin
    Logs.debug (fun m -> m "TODO better error, but failing because subpackets are longer than it's possible to sign (0xFF_FF)");
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

let parse_subpacket buf : (signature_subpacket_tag , [> `Invalid_packet]) result =
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
  signature_subpacket_tag_of_char tag_c
  |> R.reword_error (function
      |`Invalid_length -> Logs.debug (fun m -> m "inval len"); `Invalid_packet
      | err -> err
    )
  >>= begin function
    | (Signature_creation_time
      | Signature_expiration_time
      | Policy_URI
      | Preferred_symmetric_algorithms
      | Preferred_hash_algorithms
      | Preferred_compression_algorithms
      | Key_server_preferences
      )as tag ->
      let()= Logs.debug (fun m -> m "Got a whitelisted subpacket %d: %s"
                            (Char.code @@ char_of_signature_subpacket_tag tag)
                            (Cs.to_hex data)
                        )
      in
      R.ok tag
    (* TODO:
    | tag when not is_critical ->
      R.ok tag
    *)
    | tag (*TODO: when is_critical *) ->
      let()=Logs.debug (fun m -> m "Unimplemented critical subpacket %d"
                           (Char.code @@ char_of_signature_subpacket_tag tag))
      in
      R.error `Invalid_packet
  end

let parse_subpacket_data buf
  : ((signature_subpacket_tag *Cs.t)list,
     [>`Invalid_packet | `Unimplemented_algorithm of char ]) result =
  let rec loop (packets:(signature_subpacket_tag*Cs.t)list) buf =
    consume_packet_length None buf
    >>= fun (pkt, extra) ->
    parse_subpacket pkt >>= fun pkt_tag ->
    let packets = ((pkt_tag, pkt)::packets) in
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

  Cs.e_sub `Incomplete_packet buf 0 (7+hashed_len)
  >>= fun to_be_hashed ->

  (* 6+hashed_len: 2: length of unhashed subpacket data *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf (6+hashed_len)
  >>= fun unhashed_len ->

  (* 6+hashed_len+2: unhashed subpacket data *)
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2) unhashed_len
  >>= fun unhashed_subpacket_data ->
  (* TODO decide what to do with unhashed subpacket data*)
  Logs.debug (fun m -> m "Signature contains unhashed subpacket data (not handled in this implementation: %s" (Cs.to_hex unhashed_subpacket_data));

  (* 6+hashed_len+2+unhashed_len: 2: leftmost 16 bits of the signed hash value (what the fuck) *)
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2+unhashed_len) 2
  >>= fun two_byte_checksum -> (* TODO currently ignored*)
  let asf_offset = 6+hashed_len +2 + unhashed_len + 2 in
  Cs.e_sub `Incomplete_packet buf asf_offset
    ((Cs.len buf) -asf_offset)
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
          hash_algorithm = hash_algo;
          subpacket_data = subpacket_data ;
          algorithm_specific_data
         }
