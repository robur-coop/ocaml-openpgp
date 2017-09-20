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

let test_gnupg_maintainer_key () =
  let _ =
    cs_of_file "test/keys/4F25E3B6.asc"
    |> R.reword_error (fun _ -> failwith "can't open file for reading")
  >>= Openpgp.decode_public_key_block ~current_time ~armored:true
  |> R.reword_error (function `Msg s -> failwith s) in ()

let test_gnupg_key_001 () =
  ignore ((cs_of_file "test/keys/gnupg.test.001.pk.asc"
  >>= Openpgp.decode_public_key_block ~current_time)
  |> R.reword_error (function `Msg s -> failwith s)) ; ()

let test_gnupg_key_002 () =
  ignore (
    (cs_of_file "test/keys/gnupg.test.002.pk.asc"
     >>= Openpgp.decode_public_key_block ~current_time) >>| fst >>= fun pk ->
     cs_of_file "test/keys/message.001.txt.sig"
     >>= Openpgp.decode_detached_signature  >>= fun detach_sig ->
     cs_of_file "test/keys/message.001.txt" >>= fun msg ->
     Openpgp.Signature.verify_detached_cs ~current_time pk detach_sig msg
     |> R.reword_error (function `Msg s -> failwith s)
  ) ; ()

let tests =
  [
    "packet length encoding",
      [ "self-check", `Quick, test_packet_length_selfcheck ]
  ; "constants",
      [ "signature subpacket", `Slow, test_signature_subpacket_char ]
  ; "cstruct wrapper module", Alcotest_cs.tests
  ; "Parsing keys",
    [ "GnuPG maintainer key (4F25E3B6)", `Slow, test_gnupg_maintainer_key
    ; "GnuPG RSA-SC + RSA-E (001)", `Slow, test_gnupg_key_001
    ; "GnuPG RSA-SC + RSA-S (002)", `Slow, test_gnupg_key_002
    ]
  ;
  ]

let () =
  Alcotest.run "ocaml-openpgp test suite" tests
