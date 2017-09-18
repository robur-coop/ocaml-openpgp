open Types

val encode_ascii_armor : ascii_packet_type -> Cs.t -> Cs.t

val decode_ascii_armor : Cs.t -> (ascii_packet_type * Cs.t,
                                  [> `Msg of string ]) result

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
     | `Msg of string
     ])
      result

  val verify_detached_cb :
    current_time : Ptime.t ->
    transferable_public_key ->
    t ->
    (unit ->
       (Cs.t option,
       ([> `Msg of string] as 'err)) result) ->
    ([> `Good_signature ], 'err ) result

  val sign_detached_cb :
     g:Nocrypto.Rng.g -> (* PRNG *)
     current_time:Ptime.t ->
     Public_key_packet.private_key ->
     Types.hash_algorithm ->
     (Cstruct.t -> unit) * (unit -> Cstruct.t) -> (*hash_cb,hash_finalize*)
     (unit -> (* io callback for reading the data to sign *)
         (Cstruct.t option, [> `Msg of string ] as 'a
         ) Result.result) ->
     (t, 'a) Result.result
end with type t = Signature_packet.t

val packet_tag_of_packet : packet_type -> packet_tag_type

val pp_packet : Format.formatter -> packet_type -> unit

val parse_packet_body : packet_tag_type -> Cstruct.t ->
  (packet_type
   , [> `Msg of string | `Incomplete_packet ]
  ) Rresult.result

val next_packet : Cstruct.t ->
    (
      (packet_tag_type * Cstruct.t * Cstruct.t) option,
      [> `Incomplete_packet | `Msg of string ]
    ) result

val parse_packets :
  Cs.t ->
  ((packet_type * Cs.t) list
    , [> `Incomplete_packet | `Msg of string ]) result

val decode_public_key_block :
  (** [decode_public_key_block ~current_time ?armored blob] decode and validates
      the RFC 4880 transferable public key contained in [blob] using
      [current_time] to check expiry timestamps.
      If [?armored] is [Some true], the key must be ASCII-armored.
      If [?armored] is [Some false] the key must be in raw binary format.
      If [?armored] is [None], both ASCII-armored and binary are attempted.
  *)
  current_time:Ptime.t ->
  ?armored:bool -> (** None: *)
  Cs.t -> (* the public key blob *)
  ( Signature.transferable_public_key * (packet_type * Cs.t) list
  , [> `Msg of string ]) Rresult.result

val decode_detached_signature :
  (** TODO doc string*)
  ?armored:bool ->
  Cs.t -> (Signature.t, [> `Msg of string])result

val new_transferable_public_key :
  g:Nocrypto.Rng.g ->
  current_time:Ptime.t ->
  Types.openpgp_version ->
  Public_key_packet.private_key ->
  Uid_packet.t list ->
  Public_key_packet.private_key list ->
  (Signature.transferable_public_key, [> `Msg of string ]) result

val serialize_transferable_public_key :
  Signature.transferable_public_key ->
  (Cstruct.t,
    [> `Msg of string]) result
