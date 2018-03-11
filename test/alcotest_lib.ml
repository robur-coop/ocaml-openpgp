open Types
open Rresult

let a_cs = Alcotest.testable Cs.pp_hex Cs.equal
let a_cstruct = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let test_packet_length_selfcheck () =
  Alcotest.(check int32) "same int" 1234l
    (serialize_packet_length_uint32 1234l
     |> v4_packet_length_of_cs `Error >>| snd |> R.get_ok
    )

let test_signature_subpacket_char () =
  (* TODO test signature_subpacket_tag_of_signature_subpacket somehow *)
  Alcotest.(check char) "same char" 'a'
    (signature_subpacket_tag_of_char 'a' |> char_of_signature_subpacket_tag)

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
  let inner check decode ?(current_time=current_time) ~uids ~subkeys file =
    match (cs_of_file file
           |> R.reword_error (fun _ -> failwith "can't open file for reading")
           >>= decode >>= fun pk ->check pk ~uids ~subkeys >>| fun _ -> pk) with
    | Ok pk -> pk
    | Error (`Msg s) -> failwith s
  in
  let check pk ~uids ~subkeys =
    (key_has_uids uids pk >>= fun () -> key_has_subkeys subkeys pk) in
  inner check (fun cs -> cs |> Openpgp.decode_public_key_block ~current_time
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
   Alcotest.(check @@ list a_cs) "deterministic generation of secret key & sig"
     hashes
     (List.map (fun h -> Cs.of_hex h |> R.get_ok)target_hashes);
   `Good_signature
  ) |> function | Ok `Good_signature -> ()
                | Error (`Msg s) -> failwith s
                | Error `Incomplete_packet -> failwith "incomplete packet"

let test_create_pk_session_packet () : unit =
  let open Openpgp.Signature in (* TODO *)
  let open Public_key_encrypted_session_packet in
  begin match
      pk_of_file "test/keys/gnupg.test.001.pk.asc" >>= fun pk ->
      create ~key_bitlength:256 pk.root_key
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

let test_cfb_google () : unit =
  (* https://github.com/google/end-to-end/blob/master/src/javascript/crypto/e2e/openpgp/ocfb_test.html#L39-L48 *)
  let key = Cs.init 16 (fun _ -> '\x77') in
  let plain = Cs.init 51 (fun _ -> '\x66') in
  let mdc_a = Nocrypto.Hash.SHA1.digest (* the "2" below is the "quick check" *)
      Cs.(concat [Cs.init (16+2) (fun _ -> '\x1f') ; plain ] |> to_cstruct) in
  begin match begin
    Cs.of_hex "f26a24f487a3abd4d81f8072a1a2924364beba531a6b855f0239cda666eec\
               f3f47c98dc52ea3bfd60773f1a40b182577789c0149d3010d84d90f85001e\
               755b79eaaa67a52f" >>= fun ciphertext_b ->
    Cfb.decrypt ~key ciphertext_b
  end with
  | Error `Invalid_hex -> failwith "invalid hex"
  | Error (`Msg s) -> failwith s
  | Ok (mdc_b, plain_b) ->
    Alcotest.(check a_cs) "matches google's test vector" plain plain_b ;
    Alcotest.(check a_cstruct) "Check MDC aka checksum" mdc_a mdc_b
  end

let test_cfb_internal () : unit =
  let key = Cs.of_cstruct (Nocrypto.Rng.generate 16) in
  let plain = Cs.init 47 (fun i -> Char.chr (i+0x21)) in
  begin match begin
    Cfb.encrypt ~key plain >>= fun ciphertext_a ->
    Cfb.decrypt ~key ciphertext_a >>| snd
  end with
  | Ok plain_a ->
    Alcotest.(check a_cs) "Check output" plain plain_a
  | Error `Msg s -> failwith s
  end

let test_integrity_dsa () : unit =
  ["aa15898f91a57a0428d61aca60fcf244";
   "2b8d620fa5c755b1d34c570e36588d15"]
  |> test_integrity_with_algo DSA
let test_integrity_rsa () : unit =
  ["085fd7cd79b26984d46c937e6b2f12ed";
   "a86680d3768b7e4f923f87305f7b995e"]
  |> test_integrity_with_algo RSA_encrypt_or_sign

let tests =
  [
    "utilities",
    [ "packet length self-check", `Quick, test_packet_length_selfcheck ;
      "signature subpacket map", `Quick, test_signature_subpacket_map ;
      (* TODO ping the rnp people with the vectors I collected
         https://github.com/riboseinc/rnp/issues/372*)
      (* http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf *)
      "OpenPGP-CFB (Google End-to-End vector)", `Quick, test_cfb_google ;
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
