val parse_packet :
           Cstruct.t ->
           ([> `DSA of Nocrypto.Dsa.pub ],
            [> `Incomplete_packet
             | `Nonstandard_DSA_parameters
             | `Unimplemented_algorithm of char
             | `Unimplemented_version of char ])
           Rresult.result

val v4_key_id : Cs.t -> string
