open Types
open Rresult

type digest_finalizer = unit -> Cs.t
type digest_feeder =
  (Cstruct.t -> unit) * digest_finalizer

type signature_asf =
  | RSA_sig_asf of { m_pow_d_mod_n : mpi }
  | DSA_sig_asf of { r: mpi; s: mpi; }

type t = {
  (* TODO consider some fancy gadt thing here*)
  signature_type : signature_type ;
  (* note: pk algo type is inferred from asf variant *)
  (* public_key_algorithm : public_key_algorithm ; *)
  hash_algorithm : hash_algorithm ;
  (* This implementation ignores "unhashed subpacket data",
     so we only store "hashed subpacket data": *)
  subpacket_data : Cs.t ;
  algorithm_specific_data : signature_asf;
}

let digest_callback hash_algo : digest_feeder =
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

let check_signature (public_key:Public_key_packet.t)
    hash_algo
    digest_finalizer
    t  : ('ok, 'err) result =
  (* TODO handle expiry date *)
  (* TODO check backsig, see g10/sig-check.c:signature_check2 *)
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

  (* len of hashed subpacket data: *)
  (* TODO add error handling here:*)
  ichar ((Cs.len t.subpacket_data lsr 8) land 0xff) ;
  ichar ((Cs.len t.subpacket_data) land 0xff) ;

  Buffer.add_string buf (Cs.to_string t.subpacket_data) ;

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

  Cs.e_sub `Incomplete_packet buf 0 (7+hashed_len)
  >>= fun to_be_hashed ->

  (* 6+hashed_len: 2: length of unhashed subpacket data *)
  Cs.BE.e_get_uint16 `Incomplete_packet buf (6+hashed_len)
  >>= fun unhashed_len ->

  (* 6+hashed_len+2: unhashed subpacket data *)
  Cs.e_sub `Incomplete_packet buf (6+hashed_len+2) unhashed_len
  >>= fun unhashed_subpacket_data ->

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
          subpacket_data = hashed_subpacket_data ;
          algorithm_specific_data
         }
