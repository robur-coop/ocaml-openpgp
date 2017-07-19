open Types

val decode_ascii_armor : Cstruct.t -> (ascii_packet_type * Cstruct.t,
[> `Invalid
| `Invalid_crc24
| `Missing_crc24
| `Invalid_key_type | `Missing_body | `Missing_end_block | `Malformed]) result

val parse_packet : packet_type -> Cstruct.t ->
  ([> `Public_key_packet of Public_key_packet.t
   | `Public_key_subpacket of Public_key_packet.t
   | `Signature_packet of Signature_packet.t
   | `Uid_packet of Uid_packet.t
   ]
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
      (packet_type * Cstruct.t * Cstruct.t) option,
      [> `Incomplete_packet
      | `Invalid_packet
      | `Unimplemented_feature of string
      ]
    ) result

val parse_packets :
           Cs.t ->
           (
             ([> `Public_key_packet of Public_key_packet.t
              | `Public_key_subpacket of Public_key_packet.t
             | `Signature_packet of Signature_packet.t
             | `Uid_packet of Uid_packet.t ] * Cs.t)
            list,
            int *
            [> `Incomplete_packet
             | `Invalid_packet
             | `Nonstandard_DSA_parameters
             | `Unimplemented_algorithm of char
             | `Unimplemented_feature of string
             | `Unimplemented_version of char ])
           result
