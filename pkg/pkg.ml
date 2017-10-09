#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let _cli= Conf.with_pkg "cli"

(* TODO generate man file, see opam config list | grep man*)

let opams = [Pkg.opam_file ~lint_deps_excluding:(Some ["odoc"]) "opam"]

let () =
(*
  let mirage = Conf.with_pkg ~default:false "mirage" in
  let lwt = Conf.with_pkg ~default:true "lwt" in
*)
  Pkg.describe "openpgp" ~opams @@ fun c ->
  let cli = Conf.value c _cli in
  Ok [ Pkg.mllib ~api:["Openpgp"] "lib/openpgp.mllib";
       Pkg.test "test/alcotest_lib";
       Pkg.bin ~cond:cli "app/opgp"; ]
(*
  let mirage = Conf.value c mirage in
  let lwt = Conf.value c lwt in
*)
(*     ; Pkg.mllib ~cond:mirage "mirage/socks.mllib" *)
(*     ; Pkg.mllib ~cond:lwt "src/socks_lwt.mllib" *)
