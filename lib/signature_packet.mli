open Rresult

type signature_asf =
  | RSA_sig_asf of { m_pow_d_mod_n : Types.mpi } (* PKCS1-*)
  | DSA_sig_asf of { r: Types.mpi; s: Types.mpi; }

type signature_subpacket =
  | Signature_creation_time of Ptime.t
  | Signature_expiration_time of Ptime.Span.t
  | Key_expiration_time of Ptime.Span.t
  | Key_usage_flags of Types.key_usage_flags
  | Issuer_fingerprint of Types.openpgp_version * Cs.t
  | Issuer_keyid of Cs.t (* key id; rightmost 64-bits of sha1 of pk *)
  | Preferred_hash_algorithms of Types.hash_algorithm list
  | Preferred_symmetric_algorithms of Types.symmetric_algorithm list
  | Preferred_compression_algorithms of Types.compression_algorithm list
  | Embedded_signature of Cs.t (* [t] and [signature_subpacket] are mutually
                                  recursive due to Embedded_signature containing
                                  its own [t]. we store the Cs.t and defer
                                  parsing to a later point. *)
  | Key_server_preferences of Cs.t
  | Reason_for_revocation of string
  | Features of Types.feature list
  | Unimplemented_subpacket of Types.signature_subpacket_tag * Cs.t

module SubpacketMap :
sig
  type 'element t
  type tag = Types.signature_subpacket_tag
  val get_opt : tag -> 'element t -> 'element option
  val get : tag -> 'element t -> ('element, [> R.msg] ) result
  val upsert : tag -> 'element -> 'element t -> 'element t
  val add_if_empty : tag -> 'element -> 'element t -> 'element t
  val to_list : 'element t -> 'element list
  val empty : 'element t
  val cardinality : 'a t -> int
end

type t =
  { signature_type : Types.signature_type ;
    public_key_algorithm : Types.public_key_algorithm;
    hash_algorithm : Types.hash_algorithm;
    two_octet_checksum : Cs.t (** hash of what was signed. TODO the `parse` function needs to know what was parsed before it in order to validate the damned two-octet checksum. currently we just don't validate (before we check the signature). yolo. *) ;
    subpacket_data : signature_subpacket SubpacketMap.t;
    algorithm_specific_data : signature_asf;
  }

val pp : Format.formatter -> t -> unit

val hash : t -> (Cs.t -> unit) -> (unit, [> R.msg]) result

val serialize : t -> (Cs.t, [> R.msg]) result

val check_signature : Ptime.t -> Public_key_packet.t list ->
  Types.digest_finalizer ->
  t -> ([`Good_signature], [> `Incomplete_packet | R.msg]) result
(** [check_signature current_time acceptable_public_keys digest_finalizer t]
    verifies that [t] is a signature over the result of [digest_finalizer]
    issued by one of the [acceptable_public_keys],
    and not expired before [current_time].*)

val parse_packet : ?allow_embedded_signatures : bool ->
  Cs.t -> (t, [> `Incomplete_packet | R.msg] ) result

val public_key_not_expired : Ptime.t -> Public_key_packet.t -> t ->
  (unit, [> R.msg]) result

val construct_to_be_hashed_cs_manual :
  Types.openpgp_version ->
  Types.signature_type ->
  Types.public_key_algorithm ->
  Types.hash_algorithm ->
  signature_subpacket list ->
  (Cs.t, [> R.msg ]) result
