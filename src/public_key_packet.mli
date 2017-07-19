type elgamal_pubkey_asf =
          {g_pow_k_mod_p : Types.mpi
          ;m_mul_y_pow_k_mod_p: Types.mpi}


type public_key_asf =
  | DSA_pubkey_asf of Nocrypto.Dsa.pub
  | Elgamal_pubkey_asf of elgamal_pubkey_asf

type t = {
  timestamp : Cstruct.uint32 ;
  algorithm_specific_data : public_key_asf
}
val hash_public_key : pk_body:Cs.t -> (Cs.t -> unit) -> unit

val parse_packet :
           Cstruct.t ->
           ( t,
            [> `Incomplete_packet
             | `Nonstandard_DSA_parameters
             | `Unimplemented_algorithm of char
             | `Unimplemented_version of char ])
           Rresult.result

val v4_key_id : Cs.t -> string
