open Types

val encode_ascii_armor : ascii_packet_type -> Cs.t -> Cs.t

val decode_ascii_armor : Cstruct.t -> (ascii_packet_type * Cstruct.t,
[> `Invalid
| `Invalid_crc24
| `Missing_crc24
| `Invalid_key_type | `Missing_body | `Missing_end_block | `Malformed]) result

type packet_type =
  | Signature_type of Signature_packet.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t
  | Secret_key_packet of Public_key_packet.private_key
  | Secret_key_subpacket of Public_key_packet.private_key
  | Trust_packet of Cs.t

module Signature : sig
  type t
  type uid = { uid : Uid_packet.t ; certifications : Signature_packet.t list}
  type user_attribute = { certifications : Signature_packet.t list }
  type subkey = { key : Public_key_packet.t
                ; binding_signatures : Signature_packet.t list
                ; revocations : Signature_packet.t list }
  type transferable_public_key =
    {
      root_key : Public_key_packet.t
      (** One Public-Key packet *)
    ; revocations : Signature_packet.t list
      (** Zero or more revocation signatures *)
    ; uids : uid list
      (** One or more User ID packets *)
    ; user_attributes : user_attribute list
      (** Zero or more User Attribute packets *)
    ; subkeys : subkey list
      (** Zero or more subkey packets *)
    }

  val root_pk_of_packets : current_time : Ptime.t ->
    ((packet_type * Cs.t) list as 't) ->
    (transferable_public_key * 't
     ,
     [> `Extraneous_packets_after_signature
     | `Incomplete_packet
     | `Invalid_length
     | `Unimplemented_feature of string
     | `Invalid_packet
     | Cs.cstruct_err
     | `Unimplemented_version of char
             | `Invalid_signature
             | `Invalid_mpi_parameters of (Types.mpi list)
             | `Unimplemented_algorithm of char ])
      result

  val verify_detached_cb :
           current_time : Ptime.t ->
           transferable_public_key ->
           t ->
           (unit ->
            (Cs.t option,
             [> `Invalid_mpi_parameters of Nocrypto.Numeric.Z.t list
              | `Invalid_packet
              | `Invalid_signature
              | Cs.cstruct_err
              | `Unimplemented_algorithm of char ]
             as 'a)
            Rresult.result) ->
           ([> `Good_signature ], 'a) Rresult.result

  val sign_detached_cb :
     g:Nocrypto.Rng.g -> (* PRNG *)
     current_time:Ptime.t ->
     Public_key_packet.private_key ->
     Types.hash_algorithm ->
     (Cstruct.t -> unit) * (unit -> Cstruct.t) -> (*hash_cb,hash_finalize*)
     (unit -> (* io callback for reading the data to sign *)
         (Cstruct.t option, [> `Invalid_packet
                             | Cs.cstruct_err
                             | `Invalid_signature ] as 'a
         ) Result.result) ->
     (t, 'a) Result.result
end with type t = Signature_packet.t

val packet_tag_of_packet : packet_type -> packet_tag_type

val pp_packet : Format.formatter -> packet_type -> unit

val parse_packet_body : packet_tag_type -> Cstruct.t ->
  (packet_type
   ,
   [> `Incomplete_packet
   | `Invalid_packet
   | `Invalid_mpi_parameters of (Types.mpi list)
   | `Unimplemented_algorithm of char
   | `Unimplemented_version of char
   ]
  ) Rresult.result

val next_packet : Cstruct.t ->
    (
      (packet_tag_type * Cstruct.t * Cstruct.t) option,
      [> `Incomplete_packet
      | `Invalid_packet
      | `Unimplemented_feature of string
      ]
    ) result

val parse_packets :
  Cs.t ->
  ((packet_type * Cs.t) list
    , [> `Incomplete_packet
       | `Invalid_packet
       | `Invalid_mpi_parameters of (Types.mpi list)
       | `Unimplemented_algorithm of char
       | `Unimplemented_feature of string
       | `Unimplemented_version of char ]) result

val new_transferable_public_key :
  g:Nocrypto.Rng.g ->
  current_time:Ptime.t ->
  Types.openpgp_version ->
  Public_key_packet.private_key ->
  Uid_packet.t list ->
  Public_key_packet.private_key list ->
  (Signature.transferable_public_key, [> `Invalid_packet
                                       | Cs.cstruct_err
                                       | `Invalid_signature ]) result

val serialize_transferable_public_key :
  Signature.transferable_public_key ->
  (Cstruct.t,
    [> Cs.cstruct_err
     | `Invalid_packet
     | `Invalid_packet_header
     | `Invalid_signature
      | `Unimplemented_feature of string ]) result
