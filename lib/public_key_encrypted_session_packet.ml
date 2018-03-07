(* Public-Key Encrypted Session Key Packets (Tag 1)
   https://tools.ietf.org/html/rfc4880#section-5.1
*)

open Rresult

type asf =
  (* Algorithm Specific Fields for RSA encryption
     - multiprecision integer (MPI) of RSA encrypted value m**e mod n: *)
  | RSA_message of { m_pow_e : Z.t }

let pp_asf fmt asf =
  match asf with
  | RSA_message { m_pow_e } ->
    Fmt.pf fmt "%d-bit RSA" (Z.numbits m_pow_e)

type t =
  { key_id : string ; (* output of [Public_key_packet.v4_key_id pk] *)
    pk_algo : Types.public_key_algorithm ;
    asf : asf;
  }

(* TODO
   An implementation MAY accept or use a Key ID of zero as a "wild card"
   or "speculative" Key ID.  In this case, the receiving implementation
   would try all available private keys, checking for a valid decrypted
   session key.  This format helps reduce traffic analysis of messages.
*)

let pp fmt {key_id ; pk_algo; asf}: unit=
  Fmt.pf fmt "@[<v>{ key_id = %a;@  pk_algo = %a;@  asf = %a;@ }@]"
    Cs.pp_hex (Cs.of_string key_id)
    Types.pp_public_key_algorithm pk_algo
    pp_asf asf

let hash t hash_cb version : (unit, [> R.msg]) result = Ok ()

let serialize_asf = function
  | RSA_message { m_pow_e } -> Types.cs_of_mpi m_pow_e

let serialize t =
  Logs.debug (fun m -> m "serializing pk session packet %a" pp t) ;
  let w = Cs.W.create 150 in (* TODO find better avg length *)
  (* - A one-octet number giving the version number of the packet type.
    The currently defined value for packet version is "3":*)
  Cs.W.char w '\x03' ;
  (*  - An eight-octet number that gives the Key ID of the public key to
       which the session key is encrypted.  If the session key is
       encrypted to a subkey, then the Key ID of this subkey is used
       here instead of the Key ID of the primary key:*)
  Logs.debug (fun m -> m "key_id : %d = %S" (String.length t.key_id) t.key_id);
  assert (String.length t.key_id = 8) ;
  Cs.W.string w t.key_id ;
  (* - A one-octet number giving the public-key algorithm used:*)
  Cs.W.char w (Types.char_of_public_key_algorithm t.pk_algo) ;
  (* - A string of octets that is the encrypted session key.  This
       string takes up the remainder of the packet, and its contents are
       dependent on the public-key algorithm used:*)
  serialize_asf t.asf >>| Cs.W.cs w >>| fun () ->
  Cs.W.to_cs w

let parse_packet buf : (t, [> R.msg]) result =
  let rdr = Cs.R.of_cs (R.msg "TODO") buf in

  (*- A one-octet number giving the version number of the packet type.
      The currently defined value for packet version is "3":*)
  Cs.R.equal_string rdr "\x03" >>= fun () ->

  (*- An eight-octet number that gives the Key ID of the public key to
      which the session key is encrypted.  If the session key is
      encrypted to a subkey, then the Key ID of this subkey is used
      here instead of the Key ID of the primary key.*)
  Cs.R.string rdr 8 >>= fun key_id ->
  assert(String.length key_id = 8);
  Cs.R.char rdr >>= Types.public_key_algorithm_of_char
  >>= fun pk_algo ->
  Types.true_or_error (Cs.R.len rdr <= 5000)
    (fun m -> m"sanity checking of public-key encrypted session \
                packet failed; asf is larger than 5000 bytes") >>= fun () ->
  Cs.R.cs rdr (Cs.R.len rdr) >>= fun enc_session_key ->
  begin match pk_algo with
    | Types.RSA_encrypt_or_sign
    | Types.RSA_encrypt_only
      ->
      Types.consume_mpi enc_session_key >>= fun (m_pow_e, mpi_tail) ->
      Types.true_or_error (0 = Cs.len mpi_tail)
        (fun m -> m "Invalid RSA-encrypted message") >>| fun () ->
      let asf = RSA_message { m_pow_e } in
      { key_id ; pk_algo ; asf } (* TODO *)
    | _ ->
      R.error_msgf "not implemented: %a" Types.pp_public_key_algorithm pk_algo
  end

let decrypt (private_key : Public_key_packet.private_key) (t:t) =
  let open Public_key_packet in
  match private_key, t with
  | { priv_asf = RSA_privkey_asf key ;
      public = { algorithm_specific_data =
                   ( RSA_pubkey_encrypt_asf _ | RSA_pubkey_encrypt_or_sign_asf _
                     as priv_key_asf )
               ; _ }
    }, { pk_algo ; asf = RSA_message { m_pow_e }; _
       } when pk_algo = public_key_algorithm_of_asf priv_key_asf
    ->
    R.of_option ~none:(fun () -> R.error_msg "Decryption failed")
    @@ ( match Nocrypto.Rsa.PKCS1.decrypt ~mask:`Yes ~key
                 (Types.cs_of_mpi_no_header m_pow_e |> Cs.to_cstruct) with
        | exception Nocrypto.Rsa.Insufficient_key -> None
        | other -> other ) >>| Cs.of_cstruct
  | _ -> R.error_msg "Only RSA decryption is implemented"

let create ?g (pk : Public_key_packet.t) ~key_bitlength =
  let key_byte_length = key_bitlength / 8 in
  let open Public_key_packet in
  Types.true_or_error
    (Array.mem key_byte_length Nocrypto.Cipher_block.AES.ECB.key_sizes)
    (fun m -> m "Invalid key size %d for AES-OpenPGP-CFB, accepted are: %a"
        key_bitlength Fmt.(array ~sep:(unit "; ") int)
        (Array.map (fun n -> n*8) Nocrypto.Cipher_block.AES.ECB.key_sizes)
    ) >>= fun () ->
  match pk.algorithm_specific_data with
  | RSA_pubkey_encrypt_or_sign_asf key
  | RSA_pubkey_encrypt_asf key ->
    let symmetric_key = Nocrypto.Rng.generate ?g key_byte_length in
    let m_pow_e = Nocrypto.Rsa.PKCS1.encrypt ?g ~key symmetric_key
                  |> Cs.of_cstruct
                  |> Types.mpi_of_cs_no_header in
    Ok ( Cs.of_cstruct symmetric_key,
         { asf = RSA_message { m_pow_e } ;
           key_id = Public_key_packet.v4_key_id pk ;
           pk_algo = Public_key_packet.public_key_algorithm_of_asf
               pk.algorithm_specific_data ;
         } )
  | _ -> R.error_msg "Only RSA encryption supported; \
                      target public key is not an RSA key"
