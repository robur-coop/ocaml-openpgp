#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let cli = Conf.with_pkg ~default:false "cli"
(* TODO generate man file, see opam config list | grep man*)

let () =
(*
  let mirage = Conf.with_pkg ~default:false "mirage" in
  let lwt = Conf.with_pkg ~default:true "lwt" in
*)
  Pkg.describe "openpgp" @@ fun _c ->
  Ok [ Pkg.lib "pkg/META"
     ; Pkg.mllib "lib/openpgp.mllib"
     ; Pkg.test "test/alcotest_lib"
     ; Pkg.bin "app/opgp" ]
(*
  let mirage = Conf.value c mirage in
  let lwt = Conf.value c lwt in
*)
(*     ; Pkg.mllib ~cond:mirage "mirage/socks.mllib" *)
(*     ; Pkg.mllib ~cond:lwt "src/socks_lwt.mllib" *)
