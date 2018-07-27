(*TODO:*)
(* https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/modes/PGPCFBBlockCipher.java *)

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
    skip : int ;
  }

type decryption = [`decryption]
type encryption = [`encryption]

type mode = [encryption | decryption]

type _ t =
  | Decryption : state -> [`decryption] t
  | Encryption : state -> [`encryption] t

let hash t data = Nocrypto.Hash.SHA1.feed t data

let mdc_header = Cstruct.of_string "\xD3\x14"

let cs_of_opt = function None -> Cs.empty | Some cs -> cs
let opt_of_cs cs = if Cs.len cs = 0 then None else Some cs

let initialize ~key =
  assert (block_size >= 8) ;
  of_secret key >>= fun key ->
  (* 1. The feedback register (FR) is set to the IV, which is all zeros. *)
  Ok { fr = Cs.create block_size ;
       key ;
       mdc = Nocrypto.Hash.SHA1.empty ;
       prepend = None ;
       skip = 0 ;
     }

let calc_fr_e state : Cs.t =
  (* 11. FR is encrypted to produce FRE.*)
  Cs.of_cstruct (encrypt ~key:state.key (Cs.to_cstruct state.fr))

let update_mdc (type direction) (state : direction t) plain  : direction t =
  let plain_cs = Cs.to_cstruct plain in
  match state with
  | Encryption t -> Encryption {t with mdc = hash t.mdc plain_cs }
  | Decryption t -> Decryption {t with mdc = hash t.mdc plain_cs }

let pending (type direction) (t : direction t) =
  match begin match t with
    | Encryption t -> t.prepend
    | Decryption t -> t.prepend end with
  | None -> 0
  | Some prepend -> Cs.len prepend

let enc (Encryption state) plain =
  (* 2. FR is encrypted to produce FRE (FR Encrypted).  This is the
        encryption of an all-zero value: *)
  (Cs.sub (calc_fr_e state) 0 @@ Cs.len plain) >>= fun fr ->
  (* 3. FRE is xored with the first BS octets of random data prefixed to
        the plaintext to produce C[1] through C[BS], the first BS octets
        of ciphertext.*)
  Cs.xor fr plain >>| fun ciphertext ->
  (* 4. FR is loaded with C[1] through C[BS]: *)
  let t = Encryption { state with fr = ciphertext } in
  update_mdc t plain, ciphertext

let dec (Decryption state) ciphertext =
  (* encrypt FR: *)
  (Cs.sub (calc_fr_e state) 0 @@ Cs.len ciphertext)>>= fun fr ->
  let state = {state with fr } in
  Cs.xor state.fr ciphertext >>| fun plaintext ->
  let t = Decryption {state with fr = ciphertext } in
  update_mdc t plaintext, plaintext

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
     we blatantly ignore the spec and substitute with random bytes.
     ( see https://github.com/google/end-to-end/issues/151 )
     This makes us incompatible with vulnerable implementations.
     - https://eprint.iacr.org/2005/033.pdf
     - https://tools.ietf.org/html/rfc4880#page-84 *)
  let prepend = Some (Nocrypto.Rng.generate ?g 2 |> Cs.of_cstruct) in

  (* return new encryption state *)
  Ok (Encryption { state with prepend }, ciphertext)

let get_block data = Cs.split_result data block_size

let decrypt_streaming ((Decryption state) as t) ciphertext =
  let ciphertext = match state.prepend, ciphertext with
    | None, ciphertext -> ciphertext
    | Some prepend, ciphertext -> Cs.concat [prepend; ciphertext]
  in
  begin match Cs.len ciphertext >= block_size with
    | true ->
      get_block ciphertext >>= fun (c_octets, c_rest) ->
      dec t c_octets >>= fun (Decryption state, plaintext) ->
      let rest = opt_of_cs c_rest in
      if state.skip = 0 then
        Ok (plaintext, Decryption {state with prepend = None}, rest)
      else begin
        let consumed = min state.skip block_size in
        Cs.sub plaintext consumed (block_size - consumed) >>| fun decrypted ->
        ( decrypted,
          Decryption {state with prepend = None; skip = state.skip - consumed},
          rest)
      end
    | false ->
      Ok ( Cs.empty ,
           Decryption {state with prepend = opt_of_cs ciphertext } , None )
  end

let encrypt_streaming ((Encryption state) as t) plain =
  (* this is basically the same as decrypt_streaming *)
  let plain = match state.prepend, plain with
    | None, plain -> plain
    | Some prepend, plain -> Cs.concat [prepend; plain]
  in
  begin match Cs.len plain >= block_size with
    | true ->
      get_block plain >>= fun (bs_octets, bs_rest) ->
      enc t bs_octets >>| fun (Encryption state, ciphertext) ->
      ciphertext, Encryption {state with prepend = None} , opt_of_cs bs_rest
    | false ->
      Ok (Cs.empty, Encryption {state with prepend = opt_of_cs plain }, None)
  end

let finalize_decryption (Decryption state) ciphertext_opt =
  (* NOTE: there seems to be several different opinions
     about how CFB-8 is
     supposed to work... You're supposed to XOR with the
     "high bits" of FR_E. The stuff not below seems to work,
     so we take it that GnuPG took that to mean big-endian:
  *)

  (* save MDC state to avoid including the target MDC in our computed checksum*)
  let mdc = state.mdc in
  let skip = state.skip in

  let rec loop ((Decryption _) as t) mdc_acc ciphertext =
    match ciphertext with
    | Some ciphertext when pending t + Cs.len ciphertext > block_size ->
      decrypt_streaming t ciphertext >>= fun (mdc,t,ciphertext) ->
      (loop[@tailcall]) t (mdc::mdc_acc) ciphertext
    | leftover -> Ok (mdc_acc,t,leftover)
  in
  let t, last_ct =
    Decryption {state with prepend = None; skip = 0 },
    Cs.concat [ cs_of_opt state.prepend ;
                cs_of_opt ciphertext_opt ; ]
  in
  loop t [] (Some last_ct) >>= fun (mdc_lst, Decryption state, ciphertext) ->
  let mdc_lst = List.rev mdc_lst in
  let ciphertext = cs_of_opt ciphertext in
  Cs.sub (calc_fr_e state) 0 (min block_size @@ Cs.len ciphertext
                             ) >>= fun fr_e ->
  Cs.xor fr_e ciphertext >>= fun mdc_last ->
  let decrypted = mdc_lst @ [ mdc_last] |> Cs.concat in
  let plain_len = Cs.len last_ct - 2 -20 in (* 22: 2xMDC header + 20xSHA1 *)
  Cs.split_result decrypted plain_len >>= fun (plain, target_mdc) ->
  let target_mdc = Cs.to_cstruct target_mdc in
  let computed_mdc =
    Cstruct.append mdc_header @@
    ( hash mdc (Cs.to_cstruct plain) |> fun mdc ->
      (* Hash the MDC header: *)
      hash mdc mdc_header
      |> Nocrypto.Hash.SHA1.get )
  in
  Logs.debug (fun m -> m "target mdc: %a@,computed_mdc: %a"
                 Cstruct.hexdump_pp target_mdc
                 Cstruct.hexdump_pp computed_mdc
             );
  Types.true_or_error (Cstruct.len target_mdc = Cstruct.len computed_mdc)
    (fun m -> m "MDC length mismatch") >>= fun () ->
  Types.true_or_error (Cstruct.equal target_mdc computed_mdc)
    (fun m -> m "Invalid MDC during decryption") >>= fun () ->
  Cs.split_result plain skip >>| snd >>| fun plain ->
  plain

let init_decryption ~key : (decryption t, [> R.msg]) result =
  initialize ~key >>| fun state ->
  (* skip two bytes, the "quick verification" stuff *)
  Decryption {state with skip = block_size + 2 }

let full ~until_remains f original_state data =
  let rec loop data_acc state this_data =
    match this_data with
    | Some this_data when pending state + Cs.len this_data > until_remains ->
        f state this_data >>= fun (processed_data, new_state, rest) ->
        (loop[@tailcall]) (processed_data::data_acc) new_state rest
    | this_data  ->
      Ok (state, List.rev data_acc, this_data)
  in
  loop [] original_state data

let finalize_encryption (Encryption state) plaintext_opt =
  let t, plaintext =
    Encryption {state with prepend = None },
    Cs.concat [ cs_of_opt state.prepend ;
                cs_of_opt plaintext_opt ]
  in
  let mdc = hash state.mdc (Cs.to_cstruct plaintext) |> fun mdc ->
            hash mdc mdc_header
            |> Nocrypto.Hash.SHA1.get |> Cs.of_cstruct in
  (* TODO could add the min-stuff to [get_block] and replace
     the stuff below with a call to [full] (with a check for [block_size]
     in [encrypt_streaming] instead, or keeping internal shift.)*)
  let rec loop acc ((Encryption state) as t) plaintext =
    Cs.split_result plaintext @@ min block_size @@ Cs.len plaintext
    >>= fun (block, leftover) ->
    enc t block >>= fun (t, encrypted) ->
    if Cs.len block = block_size then
       (loop[@tailcall]) (encrypted::acc) t leftover
    else begin
      Cs.sub (calc_fr_e state) 0 (Cs.len block)
      >>= Cs.xor block >>= fun last ->
      Ok (List.rev @@ last::acc)
    end
  in
  (* Append MDC (aka SHA1) of everything encrypted so far: *)
  let plaintext = Cs.concat [ plaintext ; Cs.of_cstruct mdc_header ; mdc] in
  loop [] t @@ plaintext

let encrypt ?g ~key plain : (Cs.t, [> R.msg]) result =
  init_encryption ?g ~key >>= fun (t, ciphertext_start) ->
  full ~until_remains:block_size
    encrypt_streaming t (Some plain) >>= fun (t, encrypted, leftover) ->
  finalize_encryption t leftover >>| fun trailing ->
  let output = Cs.concat (ciphertext_start::Cs.concat encrypted::trailing) in
  assert(Cs.len output = block_size + 2 + Cs.len plain + 2 + 20) ;
  output

let decrypt ~key ciphertext =
  init_decryption ~key >>= fun t ->
  full ~until_remains:(2+20+block_size) decrypt_streaming t (Some ciphertext)
  >>= fun (t, decrypted, leftover) ->
  finalize_decryption t leftover >>| fun (last) ->
  let plaintext =
    Cs.concat [ (Cs.concat decrypted) ; last]
  in
  (* nonce, "quickcheck", MDC header, MDC SHA1: *)
  assert(Cs.len plaintext = Cs.len ciphertext - block_size - 2 - 2 - 20) ;
  plaintext
