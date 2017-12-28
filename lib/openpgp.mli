(** OpenPGP RFC 4880 library version %%VERSION%% *)

open Types

val encode_ascii_armor : ascii_packet_type -> Cs.t -> Cs.t
(** [encode_ascii_armor typ buf] encodes the ASCII-armored representation of
    [buf], with the header and footer lines determined by [typ]. *)


val decode_ascii_armor : Cs.t -> (ascii_packet_type * Cs.t,
                                  [> `Msg of string ]) result
(** [decode_ascii_armor buf] attempt to decode [buf] and returns the type of
    the header ("PGP PUBLIC KEY BLOCK", etc.) along with the decoded bytes. *)

type packet_type =
  | Signature_type of Signature_packet.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t
  | Secret_key_packet of Public_key_packet.private_key
  | Secret_key_subpacket of Public_key_packet.private_key
  | Trust_packet of Cs.t
  | User_attribute_packet of User_attribute_packet.t

module Signature : sig
  type t
  type uid = private { uid : Uid_packet.t
                     ; certifications : Signature_packet.t list}
  type user_attribute = private { certifications : Signature_packet.t list ;
                                  attributes : User_attribute_packet.t
                                }
  (* TODO figure out abstractions for public/private keys that let them
          share data structures (only "key" and "root_key" and "subkeys" below
          actually differ in <type subkey> / <type transferable_public_key> *)
  type subkey = private { key : Public_key_packet.t
                        ; binding_signatures : Signature_packet.t list
                        ; revocations : Signature_packet.t list }
  type private_subkey = private { secret_key : Public_key_packet.private_key
                                ; binding_signatures : Signature_packet.t list
                                ; revocations : Signature_packet.t list }
  type transferable_public_key = private
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

  type transferable_secret_key = private
    {
      root_key : Public_key_packet.private_key
      (* ; revocations : Signature_packet.t list TODO *)
    ; uids : uid list
    (*; user_attributes : user_attribute list *)
    ; secret_subkeys : private_subkey list
    }

  val transferable_public_key_of_transferable_secret_key
    : transferable_secret_key -> transferable_public_key

  val serialize : t -> (Cs.t, [> `Msg of string ]) result

  val root_sk_of_packets :
    current_time:Ptime.t ->
    ((packet_type * Cs.t) list as 't) ->
    ( transferable_secret_key * 't
    , [> `Msg of string | `Incomplete_packet]) result

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

  val verify_detached_cs :
    current_time : Ptime.t -> transferable_public_key ->
    t -> Cs.t -> ([> `Good_signature ], [> `Msg of string] ) result

  val sign_detached_cb :
     current_time:Ptime.t ->
     Public_key_packet.private_key ->
     Types.hash_algorithm ->
     (Cstruct.t -> unit) * (unit -> Cstruct.t) -> (*hash_cb,hash_finalize*)
     (unit (** io callback for reading the data to sign *) ->
         (Cstruct.t option, [> `Msg of string ] as 'a
         ) Result.result) ->
     (t, 'a) Result.result

  val sign_detached_cs :
           current_time:Ptime.t ->
           Public_key_packet.private_key ->
           Types.hash_algorithm ->
           Cs.t -> (t, [> `Msg of string ]) Result.result
end with type t = Signature_packet.t

val serialize_packet : Types.openpgp_version ->
  packet_type -> (Cstruct.t, [> `Msg of string ]) Result.result

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
  current_time:Ptime.t ->
  ?armored:bool ->
  Cs.t ->
  ( Signature.transferable_public_key * (packet_type * Cs.t) list
  , [> `Msg of string ]) Rresult.result
  (** [decode_public_key_block ~current_time ?armored blob] decode and validates
      the RFC 4880 transferable public key contained in [blob] using
      [current_time] to check expiry timestamps.
      If [?armored] is [Some true], the key must be ASCII-armored.
      If [?armored] is [Some false] the key must be in raw binary format.
      If [?armored] is [None], both ASCII-armored and binary are attempted.
  *)

val decode_secret_key_block :
           current_time:Ptime.t ->
           ?armored:bool ->
           Cs.t ->
           (Signature.transferable_secret_key * (packet_type * Cs.t) list
           , [> Public_key_packet.parse_error ]) result

val decode_detached_signature :
  ?armored:bool ->
  Cs.t -> (Signature.t, [> `Msg of string])result

val new_transferable_secret_key :
  current_time:Ptime.t ->
  Types.openpgp_version ->
  Public_key_packet.private_key ->
  Uid_packet.t list ->
  Public_key_packet.private_key list ->
  (Signature.transferable_secret_key, [> `Msg of string ]) result

val serialize_transferable_public_key :
  Signature.transferable_public_key ->
  (Cstruct.t,
   [> `Msg of string]) result

val serialize_transferable_secret_key :
  Types.openpgp_version ->
  Signature.transferable_secret_key ->
  (Cstruct.t, [> `Msg of string ]) Result.result
