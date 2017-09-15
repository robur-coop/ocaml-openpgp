open Types
open Rresult

module Alcotest = struct
  include Alcotest
  let cs = testable Cstruct.hexdump_pp Cstruct.equal
end

let test_packet_length_selfcheck () =
  Alcotest.(check int32) "same int" 1234l
    (serialize_packet_length_uint32 1234l
     |> v4_packet_length_of_cs `Error >>| snd |> R.get_ok
    )

let test_signature_subpacket_char () =
  (* TODO test signature_subpacket_tag_of_signature_subpacket somehow *)
  Alcotest.(check char) "same char" 'a'
    (signature_subpacket_tag_of_char 'a' |> char_of_signature_subpacket_tag)

let test_cs_to_list () =
  Alcotest.(check @@ list char) "\"123\" = ['1';'2';'3']]"
    ['1';'2';'3'] (Cs.to_list (Cs.of_string "123"))

let test_cs_of_list () =
  Alcotest.(check cs) "of_list |> to_list"
    (Cs.of_list ['a';'b';'c']) @@ Cs.of_string "abc"

let cs_of_file name =
  Fpath.of_string name >>= Bos.OS.File.read >>| Cs.of_string

let current_time = Ptime_clock.now ()

let test_gnupg_maintainer_key () =
  let _ =
    cs_of_file "test/keys/4F25E3B6.asc"
    |> R.reword_error (fun _ -> failwith "can't open file for reading")
  >>= Openpgp.decode_ascii_armor
  >>= (function Types.Ascii_public_key_block, cs -> Ok cs
               | _ -> failwith "Can't decode file")
  >>= Openpgp.parse_packets
  >>= Openpgp.Signature.root_pk_of_packets ~current_time
  |> R.reword_error Types.msg_of_error
  |> R.reword_error (function `Msg s -> failwith s) in ()

let tests =
  [
    "packet length encoding",
      [ "self-check", `Quick, test_packet_length_selfcheck ]
  ; "constants",
      [ "signature subpacket", `Slow, test_signature_subpacket_char ]
  ; "cstruct wrapper module",
      [ "Cs.to_list", `Quick, test_cs_to_list
      ; "Cs.of_list", `Quick, test_cs_of_list
      ]
  ; "Parsing keys",
    [ "GnuPG maintainer key (4F25E3B6)", `Slow, test_gnupg_maintainer_key
    ; ]
  ;
  ]

let () =
  Alcotest.run "my test suite" tests
