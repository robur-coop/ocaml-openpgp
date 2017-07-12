open Types

val decode_ascii_armor : Cstruct.t -> (ascii_packet_type * Cstruct.t,
[> `Invalid
| `Invalid_crc24
| `Missing_crc24
| `Invalid_key_type | `Missing_body | `Missing_end_block | `Malformed]) result

val parse_packet : packet_type -> Cstruct.t ->
    ([> `DSA of Nocrypto.Dsa.pub | `Signature | `UID of string ],
        [> `Incomplete_packet
         | `Nonstandard_DSA_parameters
         | `Unimplemented_algorithm of char
         | `Unimplemented_version of char ]) result

val next_packet : Cstruct.t ->
    (
      (packet_type * Cstruct.t * Cstruct.t) option,
      [> `Incomplete_packet
      | `Invalid_packet
      | `Unimplemented_feature of string
      ]
    ) result

