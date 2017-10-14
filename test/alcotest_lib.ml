open Types
open Rresult

let a_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

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

let key_has_uids n (tpk:Openpgp.Signature.transferable_public_key) =
  let count = List.length tpk.Openpgp.Signature.uids in
   true_or_error (n = count)
     (fun m -> m "Expected %d certified uids, got %d" n count)

let key_has_subkeys n tpk =
  let count = List.length tpk.Openpgp.Signature.subkeys in
  true_or_error (n = count)
    (fun m -> m "Expected %d subkeys, got %d" n count)

let test_broken_gnupg_maintainer_key () =
  (* This is not a valid transferable public key *)
  let _ =
  (  cs_of_file "test/keys/4F25E3B6.asc"
    |> R.reword_error (fun _ -> failwith "can't open file for reading")
    >>= Openpgp.decode_public_key_block ~current_time ~armored:true
    >>| fst >>= fun tpk ->
    key_has_uids 1 tpk >>= fun () -> key_has_subkeys 0 tpk
 ) |> R.reword_error (function `Msg s -> failwith s) in ()

let test_gnupg_key_001 () =
  let _ =
  (  cs_of_file "test/keys/gnupg.test.001.pk.asc"
     >>= Openpgp.decode_public_key_block ~current_time
     >>| fst >>= fun tpk ->
     key_has_uids 1 tpk >>= fun () -> key_has_subkeys 1 tpk
  )
  |> R.reword_error (function `Msg s -> failwith s) in ()

let test_gnupg_key_002 () =
  let _ =
    (cs_of_file "test/keys/gnupg.test.002.pk.asc"
     >>= Openpgp.decode_public_key_block ~current_time) >>| fst >>= fun pk ->
     key_has_uids 1 pk >>= fun () -> key_has_subkeys 1 pk >>= fun () ->
     cs_of_file "test/keys/message.001.txt.sig"
     >>= Openpgp.decode_detached_signature  >>= fun detach_sig ->
     cs_of_file "test/keys/message.001.txt" >>= fun msg ->
     Openpgp.Signature.verify_detached_cs ~current_time pk detach_sig msg
     |> R.reword_error (function `Msg s -> failwith s) in ()

(* TODO test that checks that we do not validate signatures with RSA_encrypt *)

let test_integrity_with_algo algo target_hashes : unit =
  let uid = "My name goes here" in
  let message_cs = Cstruct.of_string "my message" in
  let current_time = Ptime.Span.of_int_s 1234567890 |> Ptime.of_span
                     |> function Some time -> time | None -> failwith "x" in
  let g = let seed = Cs.of_string "a deterministic seed 9e5cbce8"in
    Nocrypto.Rng.create ~seed (module Nocrypto.Rng.Generators.Fortuna) in
  ( Nocrypto_entropy_unix.initialize () ; (*TODO document somewhere that this is required *)
  Public_key_packet.generate_new ~current_time ~g algo >>= fun root_sk ->
  Public_key_packet.generate_new ~current_time ~g algo >>= fun subkey_sk ->
  Openpgp.Signature.sign_detached_cs ~current_time root_sk Types.SHA384
    message_cs
  >>= (fun sig_t -> Openpgp.serialize_packet Types.V4
                      (Openpgp.Signature_type sig_t)
      )>>| Openpgp.encode_ascii_armor Types.Ascii_signature >>= fun sig_cs ->
  Openpgp.new_transferable_secret_key ~g ~current_time Types.V4 root_sk
                                      [uid] [subkey_sk] >>= fun sk ->

  Openpgp.serialize_transferable_secret_key Types.V4 sk
  >>| Openpgp.encode_ascii_armor Types.Ascii_private_key_block
  >>= fun sk_asc_cs ->
  Openpgp.decode_secret_key_block ~current_time sk_asc_cs >>| fst
  >>| Openpgp.Signature.transferable_public_key_of_transferable_secret_key
  >>= fun root_pk ->
  key_has_uids 1 root_pk >>= fun () -> key_has_subkeys 1 root_pk >>= fun () ->
  Openpgp.decode_detached_signature sig_cs
  >>= fun signature -> Openpgp.Signature.verify_detached_cs ~current_time
    root_pk signature message_cs
  >>| fun `Good_signature ->
   let hashes = List.map Nocrypto.Hash.MD5.digest [sk_asc_cs; sig_cs] in
   Logs.app (fun m -> m "%a" (Fmt.list Cstruct.hexdump_pp) hashes);
   Alcotest.(check @@ list a_cs) "deterministic generation of secret key & sig"
     hashes
     (List.map (fun h -> Cs.of_hex h |> R.get_ok)target_hashes);
   `Good_signature
  ) |> function | Ok `Good_signature -> ()
                | Error (`Msg s) -> failwith s
                | Error `Incomplete_packet -> failwith "incomplete packet"


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
    ]
  ; "constants",
      [ "signature subpacket", `Quick, test_signature_subpacket_char ]
  ; "Parsing keys",
    [ "Fail broken GnuPG maintainer key (4F25E3B6)", `Quick,
          test_broken_gnupg_maintainer_key
    ; "GnuPG RSA-SC + RSA-E (001)", `Quick, test_gnupg_key_001
    ; "GnuPG RSA-SC + RSA-S (002)", `Quick, test_gnupg_key_002
    ]
  ; "Integrity checks",
    [ "DSA: generate; sign; convert; verify", `Slow, test_integrity_dsa ;
      "RSA: generate; sign; convert; verify", `Slow, test_integrity_rsa ;
    ]
  ]

let () =
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter () ;
  Logs.(set_level @@ Some Debug);
  Alcotest.run "ocaml-openpgp test suite" tests
