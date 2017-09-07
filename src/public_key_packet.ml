open Types
open Rresult

(* RFC 4880: 5.5.2 Public-Key Packet Formats *)

type elgamal_pubkey_asf = (* for encryption *)
        { p : mpi
        ; g: mpi
        ; y: mpi}

type rsa_pubkey_asf = Nocrypto.Rsa.pub

type public_key_asf =
  | DSA_pubkey_asf of Nocrypto.Dsa.pub
  | Elgamal_pubkey_asf of elgamal_pubkey_asf
  | RSA_pubkey_sign_asf of rsa_pubkey_asf
  | RSA_pubkey_encrypt_asf of rsa_pubkey_asf
  | RSA_pubkey_encrypt_or_sign_asf of rsa_pubkey_asf

let pp_pk_asf ppf asf=
  let pp_rsa ppf (pk:rsa_pubkey_asf) = Fmt.pf ppf "%d-bit (e: %a) RSA"
      (Z.numbits pk.Nocrypto.Rsa.n) Z.pp_print pk.Nocrypto.Rsa.e in
  match asf with
  | DSA_pubkey_asf pk -> Fmt.pf ppf "%d-bit DSA key" (Z.numbits pk.Nocrypto.Dsa.p)
  | Elgamal_pubkey_asf _ -> Fmt.string ppf "El-Gamal key TODO unimplemented"
  | RSA_pubkey_sign_asf pk -> Fmt.pf ppf "%a signing key" pp_rsa pk
  | RSA_pubkey_encrypt_asf pk -> Fmt.pf ppf "%a encryptionsigning key" pp_rsa pk
  | RSA_pubkey_encrypt_or_sign_asf pk -> Fmt.pf ppf "%a encryption & signing key" pp_rsa pk

let public_key_algorithm_of_asf = function
  | DSA_pubkey_asf _ -> DSA

type private_key_asf =
  | DSA_privkey_asf of Nocrypto.Dsa.priv
  | RSA_privkey_asf of Nocrypto.Rsa.priv

type t =
  { timestamp: Ptime.t
  ; algorithm_specific_data : public_key_asf
  ; v4_fingerprint : Cs.t
  }

type private_key =
  { public : t
  ; priv_asf : private_key_asf
  }

let pp ppf t =
  (* TODO vbox / hbox *)
  Fmt.pf ppf "[public key packet: created: %a@,; %a@,; SHA1 fingerprint: %s@,]"
    Ptime.pp t.timestamp
    pp_pk_asf t.algorithm_specific_data
    (Cs.to_hex t.v4_fingerprint)

let hash_public_key pk_body (hash_cb : Cs.t -> unit) : unit =
  let to_be_hashed =
  let buffer = Buffer.create 100 in
  (* a.1) 0x99 (1 octet)*)
  let()= Buffer.add_char buffer '\x99' in
  let()=
    let lenb = Cs.len pk_body in
    (* a.2) high-order length octet of (b)-(e) (1 octet)*)
    let() = Buffer.add_char buffer ((lenb land 0xff00)
                                    lsr 8
                                    |> Char.chr) in
    (* a.3) low-order length octet of (b)-(e) (1 octet)*)
    Buffer.add_char buffer (lenb land 0xff |> Char.chr)
  in
  (* b) version number = 4 (1 octet);
     c) timestamp of key creation (4 octets);
     d) algorithm (1 octet): 17 = DSA (example)
     e) Algorithm-specific fields.*)
  let()= Buffer.add_string buffer (Cs.to_string pk_body) in
  Buffer.contents buffer |> Cs.of_string
  in
  hash_cb to_be_hashed

let v4_fingerprint ~(pk_body:Cs.t) : Cs.t =
  (* RFC 4880: 12.2.  Key IDs and Fingerprints
   A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
   followed by the two-octet packet length, followed by the entire
     Public-Key packet starting with the version field. *)
  let module H =
    (val (nocrypto_module_of_hash_algorithm SHA1))
  in
  let h = H.init () in
  let()= hash_public_key pk_body (H.feed h) in
  H.get h

let v4_key_id (pk_packet : Cs.t) : string  =
  (* in gnupg2 this is g10/keyid.c:fingerprint_from_pk*)
  (*The Key ID is the
   low-order 64 bits of the fingerprint.
  *)
  Cstruct.sub
    (v4_fingerprint ~pk_body:pk_packet)
    (Nocrypto.Hash.SHA1.digest_size - (64/8))
    (64/8)
  |> Cs.to_hex

let parse_elgamal_asf buf : (public_key_asf, 'error) result =
  (*
     Algorithm Specific Fields for Elgamal encryption:
     - MPI of Elgamal (Diffie-Hellman) value g**k mod p.
     - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.*)
  consume_mpi buf >>= fun (p, buf) ->
  consume_mpi buf >>= fun (g,buf) ->
  consume_mpi buf >>= fun (y, should_be_empty) ->
  (*y=g**x%p, where x is secret*)

  if Cs.len should_be_empty <> 0 then begin
    Logs.debug (fun m -> m "Extraneous bytes after El-Gamal MPIs: %d"
                 (Cs.len should_be_empty)) ;
    R.error `Invalid_packet
  end else

  mpis_are_prime [p;g] >>= fun _ ->

  let pk = {p ; g; y} in
  R.ok (Elgamal_pubkey_asf pk)

let parse_rsa_asf
    (purpose:[`Sign|`Encrypt|`Encrypt_or_sign])
    buf
  : (public_key_asf, 'error) result =
  consume_mpi buf >>= fun (n,buf) ->
  consume_mpi buf >>= fun (e,should_be_empty) ->

  if Cs.len should_be_empty <> 0 then begin
    Logs.debug (fun m -> m "Extra bytes after RSA MPIs") ;
    R.error `Invalid_packet
  end else

  mpis_are_prime [e] >>= fun _ ->

  let pk = Nocrypto.Rsa.{ n; e} in
  begin match purpose with
    | `Sign -> RSA_pubkey_sign_asf pk
    | `Encrypt -> RSA_pubkey_encrypt_asf pk
    | `Encrypt_or_sign -> RSA_pubkey_encrypt_or_sign_asf pk
  end |> R.ok

let parse_dsa_asf buf : (public_key_asf, 'error) result =
  consume_mpi buf >>= fun (p , buf) ->
  consume_mpi buf >>= fun (q , buf) ->
  consume_mpi buf >>= fun (gg , buf) ->
  consume_mpi buf >>= fun (y , should_be_empty) ->

  if Cs.len should_be_empty <> 0 then begin
    Logs.debug (fun m -> m "Extraneous bytes after DSA MPIs") ;
    R.error `Invalid_packet
  end else
  (* TODO validation of gg and y? *)
  (* TODO Z.numbits gg *)
  (* TODO check y < p *)

  (* TODO the public key doesn't contain the hash algo; the signature does *)
  dsa_asf_are_valid_parameters ~p ~q ~hash_algo:SHA512
  >>= fun () ->

  (* Check that p and q look like primes: *)
  mpis_are_prime [p;q]
  >>= fun _ ->

  let pk = {Nocrypto.Dsa.p;q;gg;y} in
  R.ok (DSA_pubkey_asf pk)

let cs_of_public_key_asf asf =
  begin match asf with
  | DSA_pubkey_asf {Nocrypto.Dsa.p;q;gg;y} -> [p;q;gg;y]
  | Elgamal_pubkey_asf { p ; g ; y } -> [ p; g; y ]
  | RSA_pubkey_sign_asf p
  | RSA_pubkey_encrypt_or_sign_asf p
  | RSA_pubkey_encrypt_asf p -> [ p.Nocrypto.Rsa.n ; p.Nocrypto.Rsa.e ]
  end
  |> cs_of_mpi_list |> R.get_ok

let serialize version {timestamp;algorithm_specific_data;_} =
  let buf = Buffer.create 200 in

  (* version *)
  (Buffer.add_char buf (char_of_version version) ;

   (* timestamp: *)
   (Cs.BE.e_set_ptime32 `Null (Cs.create 4) 0 timestamp |> R.get_ok
   |>Cs.to_string
   )|> Buffer.add_string buf ;

   (* public key algorithm: *)
   (* TODO this API is awkward, but basically what is missing is a "public_key_algorithm_of_packet_tag_type" function: *)
   Buffer.add_char buf (char_of_public_key_algorithm
     begin match algorithm_specific_data with
       | DSA_pubkey_asf _ -> DSA
       | RSA_pubkey_sign_asf _ -> RSA_sign_only
       | RSA_pubkey_encrypt_asf _ -> RSA_encrypt_only
       | RSA_pubkey_encrypt_or_sign_asf _ -> RSA_encrypt_or_sign
       | Elgamal_pubkey_asf _ -> Elgamal_encrypt_only
     end) ;

   Buffer.add_string buf
     (Cs.to_string
       (cs_of_public_key_asf algorithm_specific_data))
  ); Buffer.contents buf |> Cs.of_string

let parse_packet buf : ('a, [> `Incomplete_packet
                        | `Unimplemented_version of char
                        | `Unimplemented_algorithm of char
                        ]) result =
  (* 1: '\x04' *)
  v4_verify_version buf >>= fun()->

  (* 4: key generation time *)
  Cs.BE.e_get_ptime32 `Incomplete_packet buf 1
  >>= fun timestamp ->

  (* 1: public key algorithm *)
  public_key_algorithm_of_cs_offset buf (1+4)
  >>= fun pk_algo ->

  (* MPIs / "Algorithm-Specific Fields" *)
  Cs.e_split ~start:(1+4+1) `Incomplete_packet buf 0
  >>= fun (_ , pk_algo_specific) ->
  begin match pk_algo with
    | DSA -> R.ok parse_dsa_asf
    | Elgamal_encrypt_only -> R.ok parse_elgamal_asf
    | RSA_encrypt_or_sign -> R.ok (parse_rsa_asf `Encrypt_or_sign)
    | RSA_sign_only -> R.ok (parse_rsa_asf `Sign)
    | _ ->
       let()= Logs.debug (fun m -> m "Public key parser: Unimplemented PK algo") in
       R.error (`Unimplemented_algorithm
                 (char_of_public_key_algorithm pk_algo))
  end
  >>= fun parse_asf ->
  parse_asf pk_algo_specific
  >>= fun algorithm_specific_data ->
  R.ok { timestamp ; algorithm_specific_data ;
         v4_fingerprint = v4_fingerprint ~pk_body:buf}

let generate_new ~(g:Nocrypto.Rng.g) ~(current_time:Ptime.t) key_type =
  begin match key_type with
  | DSA ->
    let priv = Nocrypto.Dsa.generate ~g `Fips2048 in
    let pub  = Nocrypto.Dsa.pub_of_priv priv in
    Ok (DSA_privkey_asf priv, DSA_pubkey_asf pub)
  | RSA_sign_only ->
    let priv = Nocrypto.Rsa.generate ~g ~e:(Z.of_int 65537) 2048 in
    Ok (RSA_privkey_asf priv, RSA_pubkey_sign_asf (Nocrypto.Rsa.pub_of_priv priv))
  | RSA_encrypt_or_sign ->
    let priv = Nocrypto.Rsa.generate ~g ~e:(Z.of_int 65537) 2048 in
    Ok (RSA_privkey_asf priv, RSA_pubkey_encrypt_asf (Nocrypto.Rsa.pub_of_priv priv))
  | RSA_encrypt_only ->
    let priv = Nocrypto.Rsa.generate ~g ~e:(Z.of_int 65537) 2048 in
    Ok (RSA_privkey_asf priv, RSA_pubkey_encrypt_or_sign_asf (Nocrypto.Rsa.pub_of_priv priv))
  | Elgamal_encrypt_only ->
    Logs.err (fun m -> m "Elgamal key generation not supported") ;
    Error `Invalid_packet
  end
  >>= fun (priv_asf,pub) ->
  let temp = {timestamp = current_time
             ; algorithm_specific_data = pub
             ; v4_fingerprint = Cs.create 0}
  in
  Ok {public = {temp with
                v4_fingerprint = v4_fingerprint ~pk_body:(serialize V4 temp)
               }
     ; priv_asf}

let public_of_private (priv_key : private_key) : t =
  priv_key.public
