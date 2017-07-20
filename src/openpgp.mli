open Types

val decode_ascii_armor : Cstruct.t -> (ascii_packet_type * Cstruct.t,
[> `Invalid
| `Invalid_crc24
| `Missing_crc24
| `Invalid_key_type | `Missing_body | `Missing_end_block | `Malformed]) result

module Signature : sig
  include module type of Signature_packet
  val verify :
(packet_tag_type * Cs.t) list ->
           Public_key_packet.t ->
           ([> `Good_signature ],
            [> `Extraneous_packets_after_signature
            | `Incomplete_packet
            | `Invalid_packet
            | `Unimplemented_version of char
             | `Invalid_signature
             | `Nonstandard_DSA_parameters
             | `Unimplemented_algorithm of char ])
           result
end

type packet_type =
  | Signature_packet of Signature.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t

val packet_tag_of_packet : packet_type -> packet_tag_type

val parse_packet : packet_tag_type -> Cstruct.t ->
  (packet_type
   ,
   [> `Incomplete_packet
   | `Invalid_packet
   | `Nonstandard_DSA_parameters
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
             | `Nonstandard_DSA_parameters
             | `Unimplemented_algorithm of char
             | `Unimplemented_feature of string
             | `Unimplemented_version of char ])
           result

