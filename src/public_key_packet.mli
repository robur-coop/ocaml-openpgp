type public_key_asf =
  | DSA_pubkey_asf of Nocrypto.Dsa.pub
  | Elgamal_pubkey_asf of {p: Types.mpi ; g: Types.mpi; y: Types.mpi}
  | RSA_pubkey_sign_asf of Nocrypto.Rsa.pub
  | RSA_pubkey_encrypt_asf of Nocrypto.Rsa.pub
  | RSA_pubkey_encrypt_or_sign_asf of Nocrypto.Rsa.pub

val public_key_algorithm_of_asf : public_key_asf -> Types.public_key_algorithm

type t = {
  timestamp : Ptime.t ; (** Key creation timestamp *)
  algorithm_specific_data : public_key_asf ;
  v4_fingerprint : Cs.t (** SHA1 hash of the public key *)
}

type private_key_asf =
  | DSA_privkey_asf of Nocrypto.Dsa.priv
  | RSA_privkey_asf of Nocrypto.Rsa.priv
  | Elgamal_privkey_asf of { x: Types.mpi}

type private_key = {
  public : t ;
  priv_asf : private_key_asf
}

val pp : Format.formatter -> t -> unit
val pp_secret : Format.formatter -> private_key -> unit

val hash_public_key : t -> (Cs.t -> unit) -> unit

type parse_error =
  [ `Incomplete_packet
  | `Invalid_packet
  | `Invalid_mpi_parameters of (Types.mpi list)
  | `Unimplemented_algorithm of char
  | `Unimplemented_version of char ]

val parse_packet : Cstruct.t -> ( t, [> parse_error ]) result

val parse_secret_packet : Cstruct.t -> (private_key, [> parse_error] ) result

val serialize : Types.openpgp_version -> t -> (Cs.t,[> Cs.cstruct_err]) result

val v4_key_id : t -> string

val generate_new : g:Nocrypto.Rng.g ->
  current_time:Ptime.t ->
  Types.public_key_algorithm ->
  (private_key, [> `Invalid_packet | Cs.cstruct_err]) Result.result

val public_of_private : private_key -> t
