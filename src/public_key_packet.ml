open Types
open Rresult

(* RFC 4880: 5.5.2 Public-Key Packet Formats *)

let v4_fingerprint (pk_packet:Cs.t) : Cs.t =
  (* RFC 4880: 12.2.  Key IDs and Fingerprints
   A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
   followed by the two-octet packet length, followed by the entire
     Public-Key packet starting with the version field. *)
  let to_be_hashed =
  let buffer = Buffer.create 100 in
  (* a.1) 0x99 (1 octet)*)
  let()= Buffer.add_char buffer '\x99' in
  let()=
    let lenb = Cs.len pk_packet in
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
  let()= Buffer.add_string buffer (Cs.to_string pk_packet) in
  Buffer.contents buffer |> Cs.of_string
  in
  Nocrypto.Hash.SHA1.digest to_be_hashed

let v4_key_id (pk_packet : Cs.t) : string  =
  (*The Key ID is the
   low-order 64 bits of the fingerprint.
  *)
  Cstruct.sub
    (v4_fingerprint pk_packet)
    (Nocrypto.Hash.SHA1.digest_size - (64/8))
    (64/8)
  |> Cs.to_hex

let parse_dsa_asf buf : ([> `DSA of Nocrypto.Dsa.pub], 'error) result =
  consume_mpi buf >>= fun (p , buf) ->
  consume_mpi buf >>= fun (q , buf) ->
  consume_mpi buf >>= fun (gg , buf) ->
  consume_mpi buf >>= fun (y , buf) ->
  (* TODO Z.probab_prime p *)
  (* TODO Z.probab_prime q *)
    (* TODO > val Nocrypto.Numeric.pseudoprime : Z.t -> bool *)

  (* TODO Z.numbits gg *)
  (* TODO Z.numbits y *)

  (* DSA keys MUST also be a multiple of 64 bits,
     and the q size MUST be a multiple of 8 bits. *)
  (* 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash *)
  begin match Z.numbits p , Z.numbits q with
    | 1024 , 160 -> R.ok ()
    | 2048 , 224 -> R.ok ()
    | 2048 , 256 -> R.ok ()
    | 3072 , 256 -> R.ok ()
    | _ , _ -> R.error `Nonstandard_DSA_parameters
  end
  >>= fun () ->
  let pk : Nocrypto.Dsa.pub = {p;q;gg;y} in
  R.ok (`DSA pk)

let parse_packet buf : ('a, [> `Incomplete_packet
                        | `Unimplemented_version of char
                        | `Unimplemented_algorithm of char
                        ]) result =
  (* 1: '\x04' *)
  Cs.e_get_char `Incomplete_packet buf 0
  >>= fun version ->
  if version <> '\x04' then
    R.error (`Unimplemented_version version)
  else

  (* 4: key generation time *)
  Cs.BE.e_get_uint32 `Incomplete_packet buf 1
  >>= fun timestamp ->

  (* 1: public key algorithm *)
  Cs.e_get_char `Incomplete_packet buf (1+4)
  >>= fun pk_algo_c ->
  public_key_algorithm_of_char pk_algo_c
  |> R.reword_error (function _ -> `Unimplemented_algorithm pk_algo_c)
  >>= fun pk_algo ->

  (* MPIs / "Algorithm-Specific Fields" *)
  Cs.e_split ~start:(1+4+1) `Incomplete_packet buf 0
  >>= fun (_ , pk_algo_specific) ->
  begin match pk_algo with
    | DSA -> parse_dsa_asf pk_algo_specific
    | _ -> R.error (`Unimplemented_algorithm pk_algo_c)
  end
