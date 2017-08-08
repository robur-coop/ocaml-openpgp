type output_verbosity = Loglevel_normal | Loglevel_quiet | Loglevel_verbose | Loglevel_debug

let do_verify detached =
  raise (Invalid_argument "a")

open Cmdliner

let docs = Manpage.s_common_options

let pk =
  let doc = "TODO pk doc" in
  Arg.(required & opt (some string) None & info ["pk"] ~docs ~doc)

let help_secs = [
  `S "DESCRIPTION" ;
  `P "$(tname) is a commandline interface to the Ocaml OpenPGP library." ;
  `S Manpage.s_common_options;
  `P "Common options include output verbosity level TODO" ;
  `S Manpage.s_bugs;
  `P "Please report bugs on the issue tracker at <https://github.com/cfcs/ocaml-openpgp/issues>"
]

let verbosity_opt =
  let debug =
    let doc = "Output full debugging information" in
    Loglevel_debug, Arg.info ["debug"] ~docs ~doc
  in
  let quiet =
    let doc = "Suppress output" in
    Loglevel_quiet, Arg.info ["q";"quiet"] ~docs ~doc
  in
  let verbose =
    let doc = "Output verbose informational messages" in
    Loglevel_verbose, Arg.info ["v"; "verbose"] ~docs ~doc
  in
  Arg.(last & vflag_all [Loglevel_normal] [debug; quiet; verbose])

let verify_cmd =
  let doc = "TODO verify cmd doc" in
  let man = [
    `S Manpage.s_description ;
    `P "Verify a signature." ;
    `S "USAGE" ;
    `P "$(tname) --pk PUBLIC_KEY.ASC DETACHED_SIGNATURE.ASC FILE" ;
    `P "$(tname) --pk PUBLIC_KEY.ASC FILE_WITH_INLINE_SIGNATURE" ;
    `Blocks help_secs ]
  in
  Term.(const do_verify $ pk),
  Term.info "verify" ~doc ~sdocs:Manpage.s_common_options ~exits:Term.default_exits ~man


(*in
  Term.(pure cli_main $ pk),
  Term.info "opgp" ~version:"%%VERSION_NUM%%" ~doc ~man
*)

let cmds = [verify_cmd]

let () =
  Term.(exit @@ eval_choice verify_cmd cmds)
