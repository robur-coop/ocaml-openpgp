let cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal
let polymorphic () =
    Alcotest.testable (fun fmt _ -> Fmt.pf fmt "[polymorphic variant]")
      (fun (a:'t) (b:'t) -> 0 = compare a b)

let test_to_list () =
  Alcotest.(check @@ list char) "\"123\" = ['1';'2';'3']]"
    ['1';'2';'3'] (Cs.to_list (Cs.of_string "123"))

let test_of_list () =
  Alcotest.(check cs) "of_list |> to_list"
    (Cs.of_list ['a';'b';'c']) @@ Cs.of_string "abc"

let test_cs_w () =
  Alcotest.(check cs) "Cs.W"
    (Cs.of_string ("a" ^ "bcd"^ "EFG" ^ "1234"))
       (let w = Cs.W.create 2 in
        Cs.W.char w 'a';
        Cs.W.str w "bcd";
        Cs.W.cs w (Cs.of_string "EFG") ;
        ignore @@ Cs.W.e_ptimespan32 `TODO w (Ptime.Span.of_int_s 0x31323334) ;
        Cs.W.to_cs w |> Cs.W.of_cs |> Cs.W.to_cs
       )

let test_e_is_empty () =
  Alcotest.(check @@ result unit reject) "empty"
    (Ok ()) (Cs.e_is_empty `e (Cs.of_string "")) ;
  Alcotest.(check @@ result unit (polymorphic ())) "not empty"
    (Error `e) (Cs.e_is_empty `e (Cs.of_string "a"))

let test_strip_leading_char () =
  Alcotest.(check cs) "aaaabc -> bc" (Cs.of_string "bc")
    (Cs.of_string "aaaabc" |> Cs.strip_leading_char 'a')

let tests =
  [ "Cs.to_list", `Quick, test_to_list
  ; "Cs.of_list", `Quick, test_of_list
  ; "Cs.W", `Quick, test_cs_w
  ; "Cs.e_is_empty", `Quick, test_e_is_empty
  ; "Cs.strip_leading_char", `Quick, test_strip_leading_char
  ]
