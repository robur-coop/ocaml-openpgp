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

let tests =
  [
    "packet length encoding",
      [ "self-check", `Slow, test_packet_length_selfcheck ]
  ; "constants",
      [ "signature subpacket", `Slow, test_signature_subpacket_char ]
  ; "cstruct wrapper module",
      [ "Cs.to_list", `Quick, test_cs_to_list
      ; "Cs.of_list", `Quick, test_cs_of_list
      ]
  ;
  ]

let () =
  Alcotest.run "my test suite" tests
