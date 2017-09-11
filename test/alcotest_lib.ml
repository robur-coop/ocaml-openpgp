open Types
open Rresult

let test_packet_length_selfcheck () =
  Alcotest.(check int32) "same int" 1234l
    (serialize_packet_length_uint32 1234l
     |> v4_packet_length_of_cs `Error >>| snd |> R.get_ok
    )

let test_signature_subpacket_char () =
  Alcotest.(check char) "same char" 'a'
    (signature_subpacket_tag_of_char 'a' |> char_of_signature_subpacket_tag)

let tests =
  [
    "packet length encoding",
      ["self-check", `Slow, test_packet_length_selfcheck ];
    "constants",
      ["signature subpacket", `Slow, test_signature_subpacket_char];
  ]

let () =
  Alcotest.run "my test suite" tests
