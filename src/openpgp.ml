open Rresult
open Types
open Printf (* TODO only for debugging *)

(* TODO
   BEGIN PGP
       MESSAGE
       PRIVATE KEY BLOCK
       MESSAGE, PART X/Y
       MESSAGE, PART X
       SIGNATURE
*)
let begin_public_key_block = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----"
let end_public_key_block = Cstruct.of_string "-----END PGP PUBLIC KEY BLOCK-----"

type packet_type =
  | Signature_packet of Signature_packet.t
  | Public_key_packet of Public_key_packet.t
  | Public_key_subpacket of Public_key_packet.t
  | Uid_packet of Uid_packet.t

let packet_tag_of_packet = begin function
  | Signature_packet _ -> Signature_tag
  | Public_key_packet _ -> Public_key_tag
  | Public_key_subpacket _ -> Public_key_subpacket_tag
  | Uid_packet _ -> Uid_tag
  end

let decode_ascii_armor (buf : Cstruct.t) =
  (* see https://tools.ietf.org/html/rfc4880#section-6.2 *)
  let max_line_length = 73 in
  Cs.index buf ~max_offset:max_line_length '\n'
  |> R.of_option ~none:(fun () -> Error `Invalid)
  >>= fun type_len ->
  begin match Cs.sub buf 0 type_len with
  | b when Cstruct.equal b begin_public_key_block -> Ok Ascii_public_key_block
  | _ -> Error `Invalid_key_type
  end
  >>= fun pkt_type ->

  (* skip additional headers (like "Version:") *)
  Cs.find ~offset:type_len buf Cs.(of_string "\n\n")
  |> R.of_option ~none:(fun()-> Error `Missing_body)
  >>= fun header_end ->
  let header_end = header_end + String.(length "\n\n") in (* TODO add a Cs.find that includes length of matched needle *)

  begin match pkt_type with
  | Ascii_public_key_block ->
    Cs.find ~offset:header_end buf end_public_key_block
    |> R.of_option ~none:(fun()-> Error `Missing_end_block)
  | Ascii_private_key_block
  | Ascii_message
  | Ascii_message_part_x _
  | Ascii_message_part_x_of_y _
  | Ascii_signature ->
     Error `Malformed (* TODO `Not_implemented *)
  end
  >>= fun packet_end ->

  Cs.find buf ~offset:header_end ~max_offset:packet_end Cs.(of_string "\n=")
  |> R.of_option ~none:(fun()-> Error `Missing_crc24)
  >>= fun body_end ->
  let body_end = body_end + String.(length "\n") in

  (* 4: length of base64-encoded crc24 *)
  Cs.sub buf (body_end+String.(length "=")) 4 (* TODO catch exception *)
  |> Nocrypto.Base64.decode
  |> R.of_option ~none:(fun()-> Error `Invalid)
  >>= fun target_crc ->

  let out_buf = Cs.(create ((body_end - header_end)/4*3)) in
  let rec fill_out_buf offset decoded_offset =
    if offset >= body_end
    then Ok (Cs.sub out_buf 0 decoded_offset)
    else
    Cs.index buf ~offset ~max_offset:(min (offset+max_line_length) body_end) '\n'
    |> R.of_option ~none:(fun() -> Error `Invalid)
    >>= fun next_line ->
    let line_length = (next_line - offset) in
    Nocrypto.Base64.decode Cs.(sub buf offset line_length)
    |> R.of_option ~none:(fun() -> Error `Invalid)
    >>= fun decoded ->
    let decoded_len = Cs.len decoded in
    Cs.blit decoded 0 out_buf decoded_offset decoded_len
    ; fill_out_buf (next_line+1) (decoded_offset + decoded_len)
  in
  fill_out_buf header_end 0
  >>= fun decoded ->
  if Cs.equal (crc24 decoded) target_crc
  then Ok (pkt_type, decoded)
  else
    Error `Invalid_crc24

let parse_packet packet_tag pkt_body : (packet_type,'error) result =
  begin match packet_tag with
    | Public_key_tag ->
      Public_key_packet.parse_packet pkt_body
      >>| fun pkt -> Public_key_packet pkt
    | Public_key_subpacket_tag ->
      Public_key_packet.parse_packet pkt_body
      >>| fun pkt -> Public_key_subpacket pkt
    | Uid_tag ->
      Uid_packet.parse_packet pkt_body
      >>| fun pkt -> Uid_packet pkt
    | Signature_tag ->
      Signature_packet.parse_packet pkt_body
      >>| fun pkt -> Signature_packet pkt
  end

let next_packet (full_buf : Cs.t) :
  ((packet_tag_type * Cs.t * Cs.t) option,
   [>`Invalid_packet
   | `Unimplemented_feature of string
   | `Incomplete_packet]) result =
  if Cs.len full_buf = 0 then Ok None else
  consume_packet_header full_buf
  |> R.reword_error (function
      |`Incomplete_packet as i -> i
      |`Invalid_packet_header -> `Invalid_packet)
  >>= begin function
  | { length_type ; packet_tag; _ } , pkt_header_tl ->
    consume_packet_length length_type pkt_header_tl
    |> R.reword_error (function
        | `Invalid_length -> `Invalid_packet
        | `Incomplete_packet as i -> i
        | `Unimplemented_feature_partial_length ->
      `Unimplemented_feature "partial length")
      >>= fun (pkt_body, next_packet) ->
      Ok (Some (packet_tag , pkt_body, next_packet))
  end

let parse_packets cs : (('ok * Cs.t) list, int * 'error) result =
  (* TODO: 11.1.  Transferable Public Keys *)
  let rec loop acc cs_tl =
    next_packet cs_tl
    |> R.reword_error (fun a -> cs_tl.Cstruct.off, a)
    >>= begin function
      | Some (packet_type , pkt_body, next_tl) ->
        (parse_packet packet_type pkt_body
        |> R.reword_error (fun e -> List.length acc , e))
        >>= fun parsed ->
        loop ((parsed,pkt_body)::acc) next_tl
      | None ->
        R.ok (List.rev acc)
    end
  in
  loop [] cs

module Signature =
struct
  include Signature_packet

let verify
    (previous_packets : (packet_tag_type * Cs.t) list)
    (public_key : Public_key_packet.t) :
  ('ok , 'error) result
  =
  (* this would be a good place to wonder what kind of crack the spec people smoked while writing 5.2.4: Computing Signatures...*)
  let verify_pair (this_pair: (packet_tag_type * Cs.t) list) : ('ok,'error) result =
    (* RFC 4880: 11.1 Transferable Public Keys *)

    (* RFC 4880: - One Public-Key packet: *)
    begin match this_pair with
      | (Public_key_tag, pub_cs)::tl ->
        R.ok (pub_cs, tl)
      | _ -> R.error `Invalid_signature
    end
    >>= fun (pub_cs , packets) ->

    (* check that the root public key in the input matches
       the expected public key.
       In GnuPG they check the keyid (64bits of the SHA1). In some cases. Sometimes they don't check at all.
       (gnupg2/g10/sig-check.c:check_key_signature2 if feel like MiTM'ing some package managers)
       We compare the public key MPI data.
       In contrast we don't check the timestamp.
       Pick your poison.
    *)
    Public_key_packet.parse_packet pub_cs
    |> R.reword_error (function _ -> `Invalid_signature)
    >>= begin function
      | u when u.Public_key_packet.algorithm_specific_data
               = public_key.Public_key_packet.algorithm_specific_data ->
        (* TODO verify expiry date also? *)
        R.ok u
      | _ -> R.error `Invalid_signature
    end
    >>= fun this_pk ->

    let find_sig_pair ?needle_two (needle_one:packet_tag_type) (haystack:(packet_tag_type*Cs.t)list) =
    (* finds pairs (needle_one, needle_two) at the head of haystack
       if needle_two is None, it ignored
*)
    let rec loop acc (haystack : (packet_tag_type * Cs.t) list) =
      begin match haystack with
        | (n_one,cs_one)::(n_two,cs_two)::tl
          when n_one = needle_one && (Some n_two = needle_two) ->
              loop ((cs_one,Some cs_two)::acc) tl
        | (n_one,cs_one)::tl
          when n_one = needle_one ->
          loop ((cs_one,None)::acc) tl
        | ([] as tl|_::tl) -> (List.rev acc), tl
      end
    in
    loop [] haystack
    in

    let first_sigs = find_sig_pair Signature_tag packets in
    

    (* Get next Signature packet: *)
    begin try
        R.ok @@ (packets |> List.find
          (function (Signature_tag,_) -> true |_ ->false))
    with
    | Not_found -> R.error `Invalid_signature
    end
     >>= fun (_, sig_cs) ->
    parse_packet sig_cs
    |> R.reword_error (function _ -> `Invalid_signature)
    >>= fun signature ->

    (* set up hashing with this signature: *)
    let (hash_cb, hash_final) =
    Signature_packet.digest_callback signature.hash_algorithm
  in

  (* now that we have a hashing context, digest the root pubkey: *)
    let()= Public_key_packet.hash_public_key ~pk_body:pub_cs hash_cb in

  (* TODO should implement signature target subpacket parsing*)
  (* RFC 4880 5.2.4: Computing Signatures:
When a signature is made over a key, the hash data starts with the
   octet 0x99, followed by a two-octet length of the key, and then body
   of the key packet.  (Note that this is an old-style packet header for
   a key packet with two-octet length.)  A subkey binding signature
   (type 0x18) or primary key binding signature (type 0x19) then hashes
   the subkey using the same format as the main key (also using 0x99 as
   the first octet).  Key revocation signatures (types 0x20 and 0x28)
       hash only the key being revoked. *)

  (* TODO RFC 4880: - Zero or more revocation signatures: *)
  (* revocation keys are detailed here:
     https://tools.ietf.org/html/rfc4880#section-5.2.3.15 *)
  let rec find_revocation_sigs acc : 'a -> 'b =
    begin function
      | (Signature_tag , revocation_sig)::tl ->
        find_revocation_sigs (revocation_sig::acc) tl
      | _::tl -> R.ok (List.rev acc, tl)
      | [] as tl -> R.ok (List.rev acc , tl)
    end
  in
  find_revocation_sigs [] packets
  >>= fun (revocation_sigs, packets) ->

  (* RFC 4880: - One or more User ID packets: *)
  let rec find_uid_sigs acc haystack =
    begin match haystack with
      | (Uid_tag, uid_cs)::(Signature_tag, uid_sig_cs)::tl ->
        find_uid_sigs ((uid_cs,uid_sig_cs)::acc) tl
      | _::tl -> R.ok (List.rev acc, tl)
      | [] as tl -> R.ok (List.rev acc, tl)
    end
  in
  find_uid_sigs [] packets
  >>= fun (uid_and_sigs , packets) ->

  (*Immediately following each User ID packet, there are zero or more
   Signature packets.  Each Signature packet is calculated on the
   immediately preceding User ID packet and the initial Public-Key
    packet.*)

  (* TODO RFC 4880: - Zero or more User Attribute packets: *)
  let rec find_user_attribute_sigs acc haystack =
    begin match haystack with
      | (User_attribute_tag, uid_cs)::(Signature_tag, uid_sig_cs)::tl ->
        find_uid_sigs ((uid_cs,uid_sig_cs)::acc) tl
      | _::tl -> R.ok (List.rev acc, tl)
      | [] as tl -> R.ok (List.rev acc, tl)
    end
  in
  find_uid_sigs [] packets
  >>= fun (user_attribute_and_sigs , packets) ->

  (* RFC 4880: Zero or more Subkey packets *)
  let rec find_subkey_sigs acc haystack =
    begin match haystack with
      | (Public_key_subpacket_tag, cs)
        ::(Signature_tag, uid_sig_cs)::tl ->
        find_uid_sigs ((cs,uid_sig_cs)::acc) tl
      | _::tl -> R.ok (List.rev acc, tl)
      | [] as tl -> R.ok (List.rev acc, tl)
    end
  in
  find_subkey_sigs [] packets
  >>= fun (subkey_and_sigs, packets) ->

    packets |>
    List.fold_left (fun acc -> fun pkt ->
      begin match acc with
        | (Error _) as err -> err (* fail early *)
        | Ok `Good_signature ->
            R.error `Extraneous_packets_after_signature
      | Ok `Partial_signature ->
      begin match pkt with
      | (Uid_tag , cs) ->
        Printf.printf "hashing a uid packet\n" ;
        (* Replace header with new one *)
        if true then ( (*TODO only for v4 sigs *)
          hash_cb @@ Cstruct.of_string "\xB4" ;
          let len = Cstruct.create 4 in
          Cstruct.BE.set_uint32 len 0 (Cs.len cs|>Int32.of_int) ;
          hash_cb len
        );
        hash_cb cs;
        R.ok `Partial_signature
      | (Public_key_subpacket_tag , _) ->
        (* TODO verify subpackets bind sigs *)
        R.ok `Partial_signature
      | (Public_key_tag , _)
      | (Signature_tag , _) ->
        printf "oh look, someone's breaking the spec\n";
        R.error `Invalid_signature
      end
      end) (R.ok `Partial_signature:>([>`Partial_signature | `Good_signature],'error)result)
    >>= fun x ->
    construct_to_be_hashed_cs signature
    >>= fun to_be_hashed ->
    let()= hash_cb to_be_hashed in
    check_signature public_key signature.hash_algorithm hash_final signature >>= fun x ->
    printf "signature got validated\n";
    R.ok x
  in
  (* TODO split up in pairs of signatures *)
  begin match previous_packets
              |> List.fold_left
                (
                  fun ((pairs,acc):
                         ((packet_tag_type*Cs.t) list list)
                         * ((packet_tag_type*Cs.t) list))
                  ->
                  fun (tag_pkt:packet_tag_type * Cs.t) ->
      begin match (tag_pkt:packet_tag_type * Cs.t) with
       | (Signature_tag , _) as signature ->
         ((List.rev (signature::acc))::pairs), []
       | _ -> (pairs, tag_pkt::acc)
      end) ([],[])
      with
      | (pairs, []) -> R.ok (List.rev pairs)
      | (_ , _) ->
        printf "EXTRAEXTRA\n";
        R.error `Extraneous_packets_after_signature
    end
    >>=
    let rec loop (pairs: (packet_tag_type * Cs.t) list list) =
      begin match pairs with
        | this_pair::tl ->
          verify_pair this_pair
          >>= fun ok ->
          begin match tl with
            | [] ->
              printf "OKOK\n";
              R.ok ok
            | _ ->
              printf "got an OK sig, going to check the tail\n";
              loop tl
          end
        | _ ->
          Printf.printf "bailing because we never got a signature\n";
          R.error `Invalid_signature
      end
    in
    loop
end
