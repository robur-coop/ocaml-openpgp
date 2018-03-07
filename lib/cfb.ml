(* https://tools.ietf.org/html/rfc4880#section-13.9 *)

(* https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/modes/PGPCFBBlockCipher.java *)

(* cipher.c:102 - MDC hashes IV too *)

(* list of clients that do not do the "quick check":
  - pycryptodome: https://github.com/Legrandin/pycryptodome/commit/f80debf2d26cfd7f30dae95f2b2a893d3a34ee8c

   list of clients that DO implement it:
   - tgpg: https://github.com/gpg/tgpg/blob/master/src/cryptglue.c#L301
*)

open Nocrypto.Cipher_block.AES.ECB
open Rresult

let of_secret cs =
  if Array.mem (Cs.len cs) key_sizes then
    Ok (of_secret (cs |> Cs.to_cstruct))
  else
    R.error_msgf "Invalid keysize passed to CFB: %d" (Cs.len cs)

type state =
  { fr : Cs.t ; (* in reverse order*)
    key : key ;
    mdc : Nocrypto.Hash.SHA1.t ;
    prepend : Cs.t option ;
  }

type decryption = [`decryption]
type encryption = [`encryption]

type mode = [encryption | decryption]

type _ t =
  | Decryption : state -> [`decryption] t
  | Encryption : state -> [`encryption] t

let initialize ~key =
  assert (block_size >= 2) ;
  of_secret key >>= fun key ->
  (* 1. The feedback register (FR) is set to the IV, which is all zeros. *)
  Ok { fr = Cs.create block_size ;
       key ;
       mdc = Nocrypto.Hash.SHA1.empty ;
       prepend = None ;
     }

let calc_fr_e state : Cs.t =
  (* 11. FR is encrypted to produce FRE.*)
  Cs.of_cstruct (encrypt ~key:state.key (Cs.to_cstruct state.fr))

let update_mdc (type direction) (state : direction t) plain  : direction t =
  let open Nocrypto.Hash.SHA1 in
  let plain_cs = Cs.to_cstruct plain in
  match state with
  | Encryption t -> Encryption {t with mdc = feed t.mdc plain_cs }
  | Decryption t -> Decryption {t with mdc = feed t.mdc plain_cs }

let enc (Encryption state) plain =
  (* 2. FR is encrypted to produce FRE (FR Encrypted).  This is the
        encryption of an all-zero value: *)
  (Cs.sub (calc_fr_e state) 0 (Cs.len plain)
  ) >>= fun fr ->
  (* 3. FRE is xored with the first BS octets of random data prefixed to
        the plaintext to produce C[1] through C[BS], the first BS octets
        of ciphertext.*)
  Cs.xor fr plain >>| fun ciphertext ->
  (* 4. FR is loaded with C[1] through C[BS]: *)
  let t = Encryption { state with fr = ciphertext } in
  update_mdc t plain, ciphertext

let dec (Decryption state) ciphertext =
  (* encrypt FR: *)
  (Cs.sub (calc_fr_e state) 0 (Cs.len ciphertext)
  )>>= fun fr ->
  let state = {state with fr } in
  Cs.xor state.fr ciphertext >>| fun plaintext ->
  let t = Decryption {state with fr = ciphertext } in
  update_mdc t plaintext, plaintext

let finalize_decryption (Decryption state) ciphertext =
  (* NOTE: there seems to be several different opinions about how CFB-8 is
     supposed to work... You're supposed to XOR with the
     "high bits" of FR_E. The stuff not below seems to work,
     so we take it that GnuPG took that to mean big-endian:
  *)
  (*little-endian: (Cs.sub (Cs.reverse @@ calc_fr_e state) 0 (Cs.len ciphertext)
    >>| Cs.reverse) >>= fun fr_e ->*)
  Cs.sub (calc_fr_e state) 0 (Cs.len ciphertext) >>= fun fr_e ->
  Cs.xor fr_e ciphertext >>| fun plain ->
  Nocrypto.Hash.SHA1.(feed state.mdc (Cs.to_cstruct plain) |> fun mdc ->
                      (* Hash the MDC header: *)
                      feed mdc (Cstruct.of_hex "\xD3\x14")
                      |> get), plain

let init_encryption ?g ~key
  : (encryption t * Cs.t, [> R.msg]) result =
 (* 1.  The feedback register (FR) is set to the IV, which is all zeros.
    2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
        encryption of an all-zero value: *)
  initialize ~key >>= fun state ->

  (*3. FRE is xored with the first BS octets of random data prefixed to
       the plaintext to produce C[1] through C[BS], the first BS octets
       of ciphertext,
    4. FR is loaded with C[1] through C[BS]: *)
  let random_data = Nocrypto.Rng.generate ?g block_size |> Cs.of_cstruct in
  enc (Encryption state) random_data >>= fun (Encryption state, ciphertext) ->

  (* From the spec:
     - 6. The left two octets of FRE get xored with the next two octets of
         data that were prefixed to the plaintext.  This produces C[BS+1]
         and C[BS+2], the next two octets of ciphertext.
     - to address the timing attack on PGP described in the links below,
     we blatantly ignore the spec and substitute with nullbytes.
     ( see https://github.com/google/end-to-end/issues/151 )
     This makes us incompatible with vulnerable implementations.
     - https://eprint.iacr.org/2005/033.pdf
     - https://tools.ietf.org/html/rfc4880#page-84 *)
  let prepend = Some (Cs.of_string "\x00\x00") in

  (* return new encryption state *)
  Ok (Encryption { state with prepend}, ciphertext)

let get_block data = Cs.split_result data block_size

let decrypt_streaming (Decryption state) ciphertext =
  let t, ciphertext =
    Decryption {state with prepend = None },
    match state.prepend with
      | None -> ciphertext
      | Some prepend -> Cs.concat [prepend; ciphertext]
  in
  get_block ciphertext >>= fun (c_octets, c_rest) ->
  dec t c_octets >>| fun (state, plaintext) ->
  (plaintext, state, c_rest)

let encrypt_streaming (Encryption state) plain =
  let t, plain =
    Encryption {state with prepend = None },
    match state.prepend with
      | None -> plain
      | Some prepend -> Cs.concat [prepend; plain]
  in
  get_block plain >>= fun (bs_octets, bs_rest) ->
  enc t bs_octets >>| fun (state, ciphertext) ->
  (ciphertext, state , bs_rest)

let init_decryption ~key data
  : (decryption t * Cs.t, [> R.msg]) result =
  initialize ~key >>= fun state ->
  decrypt_streaming (Decryption state) data >>= fun (_random, state, tl1) ->
  decrypt_streaming state tl1 >>= fun (plain, Decryption state, tl) ->
  (* skip two bytes, the "quick verification" stuff *)
  Cs.sub plain 2 (Cs.len plain -2) >>= fun plain ->
  Ok (Decryption {state with prepend = Some tl}, plain)

let full f original_state data =
  let rec loop data_acc state this_data =
    f state this_data >>= fun (next_data, new_state, rest) ->
    let next_acc = next_data :: data_acc in
    if Cs.len rest >= block_size then
      (loop[@tailcall]) next_acc new_state rest
    else Ok (new_state, next_acc, rest)
  in
  loop [] original_state data

let finalize_encryption (Encryption _ as t) plaintext =
  (* "CFB shift" encrypts with the original IV: *)
  enc t plaintext >>| fun (Encryption state, trailing) ->
  let mdc = Nocrypto.Hash.SHA1.get state.mdc in
  mdc, trailing

let encrypt ?g ~key plain
  : (Nocrypto.Hash.digest * Cs.t, [> R.msg]) result =
  init_encryption ?g ~key >>= fun (t, ciphertext_start) ->
  full encrypt_streaming t plain >>= fun (t, encrypted, leftover) ->
  finalize_encryption t leftover >>| fun (mdc, trailing) ->
  let output = Cs.concat (ciphertext_start::List.rev (trailing::encrypted)) in
  assert(Cs.len output > Cs.len plain) ;
  (mdc, output)

let decrypt ~key ciphertext =
  init_decryption ~key ciphertext >>= fun (t, first_plaintext) ->
  full decrypt_streaming t Cs.empty >>= fun (t, decrypted, leftover) ->
  finalize_decryption t leftover >>| fun (mdc, last) ->
  let plaintext =
    Cs.concat (first_plaintext::List.rev (last::decrypted))
  in
  assert(Cs.len plaintext < Cs.len ciphertext) ;
  mdc, plaintext

(*let serialize t =
(* The body of this packet consists of:*)
  (* - A one-octet version number.  The only currently defined value is "1".*)
  Cs.concat (Cs.of_char '\x01' :: List.rev t.ciphertext)

*)
