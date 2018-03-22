(* Sym. Encrypted Integrity Protected Data Packet (Tag 18)
   https://tools.ietf.org/html/rfc4880#section-5.13
*)

(* NOTE that these packets must be prefixed by one or more Session Key packets
   (either Tag 1 (Public_key_encrypted_session_key_packet) or
   Tag TODO (Symmetric key session key packet)
*)

type encrypted = [ `encrypted ]
type decrypted = [ `decrypted ]

type payload = Cs.t

type _ t =
  | Encrypted : { payload : payload ; (* encrypted payload *)
                  key : Cs.t option ; (* may not be available *)
                } -> encrypted t
  | Decrypted : { key : Cs.t ;
                  payload : payload ; (* decrypted payload *)
                } -> decrypted t

let module_name = "Sym. Encrypted Integrity Protected Data Packet"

let pp (type kind) fmt : kind t -> unit = function
  | Encrypted {payload; key = _ } ->
    Fmt.pf fmt "encrypted data packet: %a" Cs.pp_hex payload
  | Decrypted {payload ; key = _ } ->
    Fmt.pf fmt "decrypted data packet: %a" Cs.pp_hex payload

open Rresult

let parse_payload cs =
  Types.consume_packet_header cs

let create ?g ~key data =
  Cfb.encrypt ?g ~key data >>| fun payload ->
  Encrypted { payload ; key = Some key }

let serialize (Encrypted t) =
  let w = Cs.W.create (1 + Cs.len t.payload) in
  (* - A one-octet version number.  The only currently defined value is "1": *)
  Cs.W.char w '\x01' ;
  Cs.W.cs   w t.payload ;
  Ok (Cs.W.to_cs w)

let hash pkt (hash_cb : Cs.t -> unit) (_:Types.openpgp_version) =
  serialize pkt >>| hash_cb

let parse_packet (data : Cs.t) : (encrypted t, [>R.msg]) result =
  let r = Cs.R.of_cs (R.msgf "Invalid %s" module_name) data in
  Cs.R.char r >>= fun version ->
  Types.true_or_error (version = '\x01')
    (fun m -> m "Invalid version in %s" module_name) >>= fun () ->
  Cs.R.cs r (Cs.R.len r) >>= fun payload ->
  Ok (Encrypted {payload; key = None })

let decrypt ?key (Encrypted { payload ; key = stored_key }) =
  begin match key, stored_key with
    | None, None -> R.error_msgf "No key provided for %s" module_name
    | ( Some key, None
      | None, Some key) -> Ok key
    | Some provided, Some _stored -> Ok provided
  end >>= fun key -> Cfb.decrypt ~key payload
