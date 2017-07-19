#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let metas = [
  Pkg.meta_file ~install:false "pkg/META"
; Pkg.meta_file ~install:false "pkg/META.cli"
]

(* TODO generate man file, see opam config list | grep man*)

let opams =
  let opam no_lint name =
    Pkg.opam_file ~lint_deps_excluding:(Some no_lint) ~install:false name
  in
  [ opam ["logs";"fmt"
         ;"rresult";"cstruct";"nocrypto";"usane";"hex"
         ;"oUnit"] "opam";
    opam [ "opam-format";"openpgp";"cmdliner" ] "opam" ]

let () =
(*
  let mirage = Conf.with_pkg ~default:false "mirage" in
  let lwt = Conf.with_pkg ~default:true "lwt" in
*)
  Pkg.describe ~metas ~opams "openpgp" @@ fun c ->
  begin match Conf.pkg_name c with
    | "openpgp" ->
      Ok [ Pkg.lib "pkg/META"
         ;Pkg.mllib "src/openpgp.mllib"
         ;Pkg.test "test/test_lib"]
    | "openpgp-cli" ->
      Ok [ Pkg.lib "pkg/META.cli"
         ; Pkg.bin "app/opgp"]
    | other ->
      R.error_msgf "unimplemented package name: %s" other
  end
(*
  let mirage = Conf.value c mirage in
  let lwt = Conf.value c lwt in
*)
(*     ; Pkg.mllib ~cond:mirage "mirage/socks.mllib" *)
(*     ; Pkg.mllib ~cond:lwt "src/socks_lwt.mllib" *)
