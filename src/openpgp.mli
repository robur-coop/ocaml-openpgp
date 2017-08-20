open Types

val decode_ascii_armor : Cstruct.t -> (ascii_packet_type * Cstruct.t,
[> `Invalid
| `Invalid_crc24
| `Missing_crc24
| `Invalid_key_type | `Missing_body | `Missing_end_block | `Malformed]) result

module Signature : sig
  include module type of Signature_packet
  type uid = { uid : Uid_packet.t ; certifications : Signature_packet.t list}
  type user_attribute = { certifications : Signature_packet.t list }
  type subkey = { key : Public_key_packet.t ; signature : Signature_packet.t ; revocation : Signature_packet.t option }
  type transferable_public_key =
    {
    (** One Public-Key packet *)
      root_key : Public_key_packet.t
      (** Zero or more revocation signatures *)
      ; revocations : Signature_packet.t list
    (** One or more User ID packets *)
    ; uids : uid list
    (** Zero or more User Attribute packets *)
    ; user_attributes : user_attribute list
    (** Zero or more subkey packets *)
    ; subkeys : subkey list
    }
  val root_pk_of_packets : (packet_tag_type * Cs.t) list ->
    (transferable_public_key * (packet_tag_type * Cs.t) list
     ,
     [> `Extraneous_packets_after_signature
     | `Incomplete_packet
     | `Invalid_length
     | `Unimplemented_feature_partial_length
     | `Invalid_packet
     | `Unimplemented_version of char
             | `Invalid_signature
             | `Invalid_mpi_parameters of (Types.mpi list)
             | `Unimplemented_algorithm of char ])
           result
end

type packet_type =
  | Signature_type of Signature.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t

val packet_tag_of_packet : packet_type -> packet_tag_type

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
            ,
            int *
            [> `Incomplete_packet
             | `Invalid_packet
             | `Invalid_mpi_parameters of (Types.mpi list)
             | `Unimplemented_algorithm of char
             | `Unimplemented_feature of string
             | `Unimplemented_version of char ])
           result
