type elgamal_pubkey_asf =
          {p : Types.mpi
          ;g : Types.mpi
          ;y : Types.mpi}

type rsa_pubkey_asf = Nocrypto.Rsa.pub

type public_key_asf =
  | DSA_pubkey_asf of Nocrypto.Dsa.pub
  | Elgamal_pubkey_asf of elgamal_pubkey_asf
  | RSA_pubkey_sign_asf of rsa_pubkey_asf
  | RSA_pubkey_encrypt_asf of rsa_pubkey_asf
  | RSA_pubkey_encrypt_or_sign_asf of rsa_pubkey_asf

type t = {
  timestamp : Ptime.t ; (** Key creation timestamp *)
  algorithm_specific_data : public_key_asf ;
  v4_fingerprint : Cs.t (** SHA1 hash of the public key *)
}

val pp : Format.formatter -> t -> unit

val hash_public_key : Cs.t -> (Cs.t -> unit) -> unit

val parse_packet :
           Cstruct.t ->
           ( t,
             [> `Incomplete_packet
             | `Invalid_packet
             | `Invalid_mpi_parameters of (Types.mpi list)
             | `Unimplemented_algorithm of char
             | `Unimplemented_version of char ])
           Rresult.result

val serialize : Types.openpgp_version -> t -> Cs.t

val v4_key_id : Cs.t -> string
