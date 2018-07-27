open Types
open Rresult

let a_cs = Alcotest.testable Cs.pp_hex Cs.equal
let a_cstruct = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let test_s2k_count_of_char () =
  let max_count = (* from GPG src *) 65011712 in
  Alcotest.(check int) "max count" max_count (s2k_count_of_char '\255') ;
  Alcotest.(check int) "min count" 1024 (s2k_count_of_char '\000') ;
  let rec all last = function
    | '\255' -> () (* this one is checked in case above *)
    | c ->
      let next = s2k_count_of_char c in
      assert(next >= 1024) ;
      (* c is always <= 254, so this must hold: *)
      assert(next < max_count ) ;
      (* check that step >= (1<<6 = 64): *)
      assert(next >= last + 64) ;
      (* test that each is = decoded: *)
      let c2 = char_of_s2k_count next in
      assert( c = c2 ) ;
      all next (Char.chr @@ Char.code c + 1)
  in all (1024-64) '\000'

let test_packet_length_selfcheck () =
  for i = 0 to 1030 do
    let i = Int32.of_int i in
    Alcotest.(check int32) "same int" i
      (serialize_packet_length_uint32 i
       |> v4_packet_length_of_cs `Error >>| snd |> R.get_ok
      )
  done

let test_signature_subpacket_char () =
  (* TODO test signature_subpacket_tag_of_signature_subpacket somehow *)
  for i = 0 to 255 do
    let c = Char.chr i in
    Alcotest.(check char) "same char" c
      (signature_subpacket_tag_of_char c |> char_of_signature_subpacket_tag)
  done

let test_packet_header () =
  for i = 0 to 255 do
    Alcotest.(check unit) ("doesn't crash " ^ (string_of_int i)
                           ^ "->" ^ Char.(escaped @@ chr i))
      ()
      ( match Types.packet_header_of_char (Char.chr i) with | _ -> () )
  done

let test_signature_subpacket_map () =
  let open Signature_packet in
  let open SubpacketMap in
  let t1 = add_if_empty Key_expiration_time 0 empty in
  let t2 = add_if_empty Key_expiration_time 1 t1 in
  let t3 = upsert Features 3 t2 in
  let t4 = add_if_empty Key_usage_flags 8 t3 in
  let t5 = upsert Primary_user_id 2 t4 in
  let t6 = upsert Features 4 t5 in
  Alcotest.(check int) "cardinality of empty" 0 (cardinality empty) ;
  Alcotest.(check int) "cardinality" 3 (cardinality t4);
  Alcotest.(check int) "cardinality after upsert insert" 4 (cardinality t6) ;
  Alcotest.(check @@ option int) "get_opt upsert insert"
    (get_opt Primary_user_id t6) (Some 2) ;
  Alcotest.(check @@ option int) "get_opt upsert replace"
    (get_opt Features t6) (Some 4) ;
  Alcotest.(check @@ option int) "get_opt add_if_empty insert"
    (get_opt Key_usage_flags t6) (Some 8) ;
  Alcotest.(check @@ option int) "get_opt add_if_empty doesn't replace"
    (get_opt Key_expiration_time t6) (Some 0) ;
  Alcotest.(check @@ list int) "to_list keeps ordering" [0;4;8;2] (to_list t6)

let cs_of_file name =
  Fpath.of_string name >>= Bos.OS.File.read >>| Cs.of_string

let current_time = Ptime_clock.now ()

let pk_of_file path =
  cs_of_file path
  |> R.reword_error (fun _ -> failwith "can't open file for reading")
  >>= Openpgp.decode_public_key_block ~current_time ~armored:true
  >>| fst

let key_has_uids n (tpk:Openpgp.Signature.transferable_public_key) =
  let count = List.length tpk.Openpgp.Signature.uids in
   true_or_error (n = count)
     (fun m -> m "Expected %d certified uids, got %d" n count)

let key_has_subkeys n tpk =
  let count = List.length tpk.Openpgp.Signature.subkeys in
  true_or_error (n = count)
    (fun m -> m "Expected %d subkeys, got %d" n count)

let exc_check_pk, exc_check_sk =
  let inner check decode ~uids ~subkeys file =
    match (cs_of_file file
           |> R.reword_error (fun _ -> failwith "can't open file for reading")
           >>= decode >>= fun pk ->check pk ~uids ~subkeys >>| fun _ -> pk) with
    | Ok pk -> pk
    | Error (`Msg s) -> failwith s
  in
  let check pk ~uids ~subkeys =
    (key_has_uids uids pk >>= fun () -> key_has_subkeys subkeys pk)
  in
  inner check
    (fun cs -> cs |> Openpgp.decode_public_key_block ~current_time
                 ~armored:true >>| fst),
  inner (fun sk -> check
      (Openpgp.Signature.transferable_public_key_of_transferable_secret_key sk))
    (fun cs -> Openpgp.decode_secret_key_block ~current_time ~armored:true cs
      >>| fst |> R.reword_error (function
            `Incomplete_packet -> `Msg "incomplete packet" | `Msg e -> `Msg e))

let test_broken_gnupg_maintainer_key () =
  (* This is not a valid transferable public key *)
  let _ = exc_check_pk "test/keys/4F25E3B6.asc" ~uids:1 ~subkeys:0 in ()

let test_gnupg_key_001 () =
  let _= exc_check_pk "test/keys/gnupg.test.001.pk.asc" ~uids:1 ~subkeys:1 in()

let test_gnupg_key_002 () =
  let _ =
  (  let pk = exc_check_pk "test/keys/gnupg.test.002.pk.asc" ~uids:1 ~subkeys:1
     in
     cs_of_file "test/keys/message.001.txt.sig"
     >>= Openpgp.decode_detached_signature  >>= fun detach_sig ->
     cs_of_file "test/keys/message.001.txt" >>= fun msg ->
     Openpgp.Signature.verify_detached_cs ~current_time pk detach_sig msg
     |> R.reword_error (function `Msg s -> failwith s)) in ()

let test_openpgpjs_000 () =
  let _ = exc_check_pk "test/keys/openpgpjs.000.pk.asc" ~uids:1 ~subkeys:1 in()

let must_fail e f =
  match f () with
  | exception _ -> ()
  | _ -> failwith e

let test_openpgpjs_001 () =
  must_fail "test_openpgpjs_001: should fail since we do not parse encrypted \
             secret keys."
    (fun () -> exc_check_sk "test/keys/openpgpjs.001.sk.asc" ~uids:1 ~subkeys:1)

let test_openpgpjs_002 () =
  let _= exc_check_pk "test/keys/openpgpjs.002.pk.asc" ~uids:1 ~subkeys:1 in()

let test_openpgpjs_key_000 () =
  let _ = exc_check_pk "test/keys/openpgpjs.key.000.pk.asc" ~uids:1 ~subkeys:1
  in () (* TODO this armored file really contains two transferable public keys.
           API doesn't handle that atm.*)

let test_openpgpjs_key_001 () = (* revoked *)
  (* TODO this should fail *)
  must_fail "should be expired"
    (fun () ->
       exc_check_pk "test/keys/openpgpjs.key.001.pk.asc" ~uids:0 ~subkeys:0 )

let test_openpgpjs_key_002 () =
  must_fail "Should fail to parse v3"
    (fun () ->
       exc_check_pk "test/keys/openpgpjs.key.002.pk.asc" ~uids:1 ~subkeys:1 )

let test_openpgpjs_key_003 () = (*RSA with revocations*)
  let _ = exc_check_pk "test/keys/openpgpjs.key.003.pk.asc" ~uids:1 ~subkeys:1
  in ()

let test_openpgpjs_key_004 () = (* priv_key_rsa *)
  let _ = exc_check_pk "test/keys/openpgpjs.key.004.priv_key_rsa.pk.asc" ~uids:1
      ~subkeys:0 in ()

let test_openpgpjs_key_005 () = (* user_attr *)
  let _ = exc_check_pk "test/keys/openpgpjs.key.005.user_attr_key.pk.asc"
      ~uids:1 ~subkeys:0 in ()

let test_openpgpjs_key_006 () = (* embedded signature *)
  let _ = exc_check_pk "test/keys/openpgpjs.key.006.pgp_desktop_pub.pk.asc"
      ~uids:1 ~subkeys:1 in ()


(* TODO test that checks that we do not validate signatures with RSA_encrypt *)

let test_integrity_with_algo algo target_hashes : unit =
  let uid = "My name goes here" in
  let message_cs = Cs.of_string "my message" in
  let current_time = Ptime.Span.of_int_s 1234567890 |> Ptime.of_span
                     |> function Some time -> time | None -> failwith "x" in
  let g =
    let seed = Cs.of_string "a deterministic seed 9e5cbce8"
             |> Cs.to_cstruct
    in
    Nocrypto.Rng.create ~seed (module Nocrypto.Rng.Generators.Fortuna) in
  (Public_key_packet.generate_new ~current_time ~g algo >>= fun root_sk ->
  Public_key_packet.generate_new ~current_time ~g algo >>= fun subkey_sk ->
  Openpgp.Signature.sign_detached_cs ~current_time root_sk Types.SHA384
    message_cs
  >>= (fun sig_t -> Openpgp.serialize_packet Types.V4
                      (Openpgp.Signature_type sig_t)
      )>>= Openpgp.encode_ascii_armor Types.Ascii_signature >>= fun sig_cs ->
  Openpgp.new_transferable_secret_key ~current_time Types.V4 root_sk
                                      [uid] [subkey_sk] >>= fun sk ->

  Openpgp.serialize_transferable_secret_key Types.V4 sk
  >>= Openpgp.encode_ascii_armor Types.Ascii_private_key_block
  >>= fun sk_asc_cs ->
  Openpgp.decode_secret_key_block ~current_time sk_asc_cs >>| fst
  >>| Openpgp.Signature.transferable_public_key_of_transferable_secret_key
  >>= fun root_pk ->
  key_has_uids 1 root_pk >>= fun () -> key_has_subkeys 1 root_pk >>= fun () ->
  Openpgp.decode_detached_signature sig_cs
  >>= fun signature -> Openpgp.Signature.verify_detached_cs ~current_time
    root_pk signature message_cs
  >>| fun `Good_signature ->
  let hashes = List.map (fun x -> Nocrypto.Hash.MD5.digest x
                                  |> Cs.of_cstruct)
      (List.map Cs.to_cstruct [sk_asc_cs; sig_cs]) in
  Logs.app (fun m -> m "%a" (Fmt.list Cs.pp_hex) hashes);
  (* This test case ensures that we didn't forget to pass the Nocrypo rng (?g)
     somewhere - being able to deterministically generate keys from a seed is
     tremendously useful for debugging and for minimizing test vectors: *)
   Alcotest.(check @@ list a_cs) "deterministic generation of secret key & sig \
                                  (this checks against a hardcoded hash; did \
                                  you modify the key generation?)"
     (List.map (fun h -> Cs.of_hex h |> R.get_ok) target_hashes)
     hashes ;
   `Good_signature
  ) |> function | Ok `Good_signature -> ()
                | Error (`Msg s) -> failwith s
                | Error `Incomplete_packet -> failwith "incomplete packet"

let test_create_pk_session_packet () : unit =
  let open Openpgp.Signature in (* TODO *)
  let open Public_key_encrypted_session_packet in
  begin match
      pk_of_file "test/keys/gnupg.test.001.pk.asc" >>= fun pk ->
      create pk.root_key AES256
    with
    | Ok (key, t) ->
      Alcotest.(check int) "Length of generated symmetric key is 256 bits"
        256 (8 * Cs.len key) ;
      Alcotest.(check @@ result pass reject) "Can serialize the message"
        (Ok Cs.empty) (serialize t) ;
      Alcotest.(check @@ result pass reject) "Can parse the serialized message"
        (Ok t) (serialize t >>= parse_packet)
    | Error `Msg s -> failwith s
  end

let test_cfb_fixed () : unit =
  let key = Cs.of_hex "fab932fd112bc4a0184fc64c3a8c2130\
                       664c79a61a60302afae806222fc243a5" |> R.get_ok in
  let plain =
    Cs.of_string {|!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO|} in
  match begin
    Cs.of_hex "3e1723ae0500cf7514f64e743bf1fca778a2082175622f09dd3e42383b02e\
               325b54b482bb5d5e11eb06a7ee36bff3d00459fe19bf030d0f2741821bf82\
               e59c473a5dc2a21013ae345df6d25592466b01814192930c48aa"
    >>= fun ciphertext_b ->
    Cfb.decrypt ~key ciphertext_b
  end with
  | Error `Invalid_hex -> failwith "invalid hex"
  | Error (`Msg s) -> failwith s
  | Ok plain_b ->
    Alcotest.(check a_cs) "matches our fixed test vector" plain plain_b

let test_cfb_internal () : unit =
  let key = Cs.of_cstruct (Nocrypto.Rng.generate 16) in
  for plain_len = 0 to 1000 do
    let plain = Nocrypto.Rng.generate plain_len |> Cs.of_cstruct in
    begin match begin
      Cfb.encrypt ~key plain >>= fun ciphertext_a ->
      Cfb.decrypt ~key ciphertext_a
    end with
    | Ok plain_a ->
      Alcotest.(check a_cs) "Check output" plain plain_a
    | Error `Msg s -> failwith s
    end
  done

let test_literal_data_packet () : unit =
  let packet = Cs.of_string "b\x03abc\x01\x02\x03\x04abcdef"in
  match begin
    Literal_data_packet.parse packet
  end with
  | Error `Msg s -> failwith s
  | Ok (Literal_data_packet.In_memory_t (_state,acc) as t) ->
    let res = String.concat "" acc in
    Alcotest.(check @@ string) "parsing literal data packet" "abcdef" res ;
    Alcotest.(check @@ a_cs) "re-serializing"
      packet @@ Literal_data_packet.serialize t

let test_integrity_dsa () : unit =
  ["5513e173b497fdbcd5877aaf6a30b0f6" ;
   "2b8d620fa5c755b1d34c570e36588d15" ]
  |> test_integrity_with_algo DSA
let test_integrity_rsa () : unit =
  ["0e24ca0da59aaafdae0762035222fb78" ;
   "a86680d3768b7e4f923f87305f7b995e" ]
  |> test_integrity_with_algo RSA_encrypt_or_sign

let tests =
  [
    "utilities",
    [ "S2K count_of_char", `Quick, test_s2k_count_of_char ;
      "packet length self-check", `Quick, test_packet_length_selfcheck ;
      "packet header", `Quick, test_packet_header ;
      "signature subpacket map", `Quick, test_signature_subpacket_map ;
      (* TODO ping the rnp people with the vectors I collected
         https://github.com/riboseinc/rnp/issues/372*)
      (* http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf *)
      "Literal data packet", `Quick, test_literal_data_packet ;
      "OpenPGP-CFB (hardcoded verified vector)", `Quick, test_cfb_fixed ;
      "OpenPGP-CFB (internal consistency)", `Quick, test_cfb_internal ;
    ]
  ; "constants",
    [ "signature subpacket", `Quick, test_signature_subpacket_char ]
  ; "Encryption",
    [ "create encrypted session packet", `Quick, test_create_pk_session_packet
    ]
  ; "Parsing keys",
    [ "Fail broken GnuPG maintainer key (4F25E3B6)", `Quick,
          test_broken_gnupg_maintainer_key
    ; "GnuPG RSA-SC + RSA-E (001)", `Quick, test_gnupg_key_001
    ; "GnuPG RSA-SC + RSA-S (002)", `Quick, test_gnupg_key_002
    ]
  ; "OpenPGP.js test suite",
    [ "OpenPGP.js RSA-ESC + RSA-ES (000)", `Quick, test_openpgpjs_000
    ; "OpenPGP.js (001)", `Quick, test_openpgpjs_001
    ; "OpenPGP.js DSA + El-Gamal (002)", `Quick, test_openpgpjs_002
    (* https://github.com/openpgpjs/openpgpjs/blob/master/test/general/key.js *)
    ; "OpenPGP.js key.js (000)", `Quick, test_openpgpjs_key_000
    ; "OpenPGP.js key.js (001)", `Quick, test_openpgpjs_key_001
    ; "OpenPGP.js key.js, v3 pk (002)", `Quick, test_openpgpjs_key_002
    ; "OpenPGP.js key.js, revocations (003)", `Quick, test_openpgpjs_key_003
    ; "OpenPGP.js key.js, secret key (004)", `Quick, test_openpgpjs_key_004
    ; "OpenPGP.js key.js, user attr tag (005)", `Quick, test_openpgpjs_key_005
    ; "OpenPGP.js key.js, PGP Desktop pk (006)", `Quick, test_openpgpjs_key_006
    ]
  ; "Integrity checks",
    [ "DSA: generate; sign; convert; verify", `Slow, test_integrity_dsa ;
      "RSA: generate; sign; convert; verify", `Slow, test_integrity_rsa ;
    ]
  ]

let () =
  Nocrypto_entropy_unix.initialize() ;
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter () ;
  Logs.(set_level @@ Some Debug);
  Alcotest.run "ocaml-openpgp test suite" tests
