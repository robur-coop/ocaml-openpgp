open Types
open Rresult

let test_packet_length_selfcheck () =
  Alcotest.(check int32) "same int" 1234l
    (serialize_packet_length_uint32 1234l
     |> v4_packet_length_of_cs `Error >>| snd |> R.get_ok
    )

let test_signature_subpacket_char () =
  (* TODO test signature_subpacket_tag_of_signature_subpacket somehow *)
  Alcotest.(check char) "same char" 'a'
    (signature_subpacket_tag_of_char 'a' |> char_of_signature_subpacket_tag)

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

let test_gnupg_maintainer_key () =
  let _ =
  (  cs_of_file "test/keys/4F25E3B6.asc"
    |> R.reword_error (fun _ -> failwith "can't open file for reading")
    >>= Openpgp.decode_public_key_block ~current_time ~armored:true
    >>| fst >>= fun tpk ->
    key_has_uids 1 tpk >>= fun () -> key_has_subkeys 1 tpk
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
  ignore (
    (cs_of_file "test/keys/gnupg.test.002.pk.asc"
     >>= Openpgp.decode_public_key_block ~current_time) >>| fst >>= fun pk ->
     key_has_uids 1 pk >>= fun () -> key_has_subkeys 1 pk >>= fun () ->
     cs_of_file "test/keys/message.001.txt.sig"
     >>= Openpgp.decode_detached_signature  >>= fun detach_sig ->
     cs_of_file "test/keys/message.001.txt" >>= fun msg ->
     Openpgp.Signature.verify_detached_cs ~current_time pk detach_sig msg
     |> R.reword_error (function `Msg s -> failwith s)
  ) ; ()

(* TODO test that checks that we do not validate signatures with RSA_encrypt *)

let test_integrity_with_algo algo =
  let uid = "My name goes here" in
  let message_cs = Cstruct.of_string "my message" in
  let g = Nocrypto_entropy_unix.initialize() ; !Nocrypto.Rng.generator in
  (
  Public_key_packet.generate_new ~current_time ~g algo >>= fun root_sk ->
  Public_key_packet.generate_new ~current_time ~g algo >>= fun subkey_sk ->
  Openpgp.Signature.sign_detached_cs ~current_time ~g root_sk Types.SHA384
    message_cs
  >>= (fun sig_t -> Openpgp.serialize_packet Types.V4
                      (Openpgp.Signature_type sig_t)
      )>>| Openpgp.encode_ascii_armor Types.Ascii_signature >>= fun sig_cs ->
  Openpgp.new_transferable_secret_key ~g ~current_time Types.V4 root_sk
                                      [uid] [subkey_sk] >>= fun sk ->

  Openpgp.serialize_transferable_secret_key Types.V4 sk
  >>| Openpgp.encode_ascii_armor Types.Ascii_private_key_block
  >>= Openpgp.decode_secret_key_block ~current_time >>| fst
  >>| Openpgp.Signature.transferable_public_key_of_transferable_secret_key
  >>= fun root_pk ->
  key_has_uids 1 root_pk >>= fun () -> key_has_subkeys 1 root_pk >>= fun () ->
  Openpgp.decode_detached_signature sig_cs
  >>= fun signature -> Openpgp.Signature.verify_detached_cs ~current_time
                            root_pk signature message_cs
 ) |> function | Ok `Good_signature -> ()
               | Error (`Msg s) -> failwith s
               | Error `Incomplete_packet -> failwith "incomplete packet"

let test_integrity_dsa () = test_integrity_with_algo DSA
let test_integrity_rsa () = test_integrity_with_algo RSA_encrypt_or_sign

let tests =
  [
    "packet length encoding",
      [ "self-check", `Quick, test_packet_length_selfcheck ]
  ; "constants",
      [ "signature subpacket", `Quick, test_signature_subpacket_char ]
  ; "Parsing keys",
    [ "GnuPG maintainer key (4F25E3B6)", `Quick, test_gnupg_maintainer_key
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
