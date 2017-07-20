open OUnit2

(** TODO: OUnit2 should detect test suites automatically. *)
let all_suites = [
  "PublicKeyPacket" >::: Test_publickey.suite;
  ]

let () =
  Logs.set_level @@ Some Logs.Debug ;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ()) ;
  run_test_tt_main ("all" >::: all_suites)
