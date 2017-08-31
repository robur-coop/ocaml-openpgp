open Rresult

let do_verify _ pk_file detached_file target_file : (unit, [ `Msg of string ]) Result.result =
  let res =
  let file_cb filename =
    let content = ref (Some (Bos.OS.File.read
                               (Fpath.of_string filename|>R.get_ok) |> R.get_ok |> Cs.of_string)
                      ) in
    (fun () ->
       match !content with
       | x -> content := None; Ok x
    )
    (*
    Bos.OS.File.with_ic filepath
      (fun ic -> fun _ ->
         (fun () ->
            let buf = Bytes.create 8192 in
            match input ic buf 0 8192 with
            | exception Sys_error _ -> Ok None (* TODO not sure this is the way to go*)
            | 0 -> Ok None
            | x ->
              Printf.eprintf "got some bytes: %S!" (Bytes.to_string buf);
              Ok (Some ((Bytes.sub buf 0 x) |> Cstruct.of_bytes))
         )
      ) 0
    |> R.reword_error (fun e -> Printf.printf "whatt\n";e) |> R.get_ok
    *)
  in
  Bos.OS.File.read (Fpath.of_string pk_file|>R.get_ok) >>| Cs.of_string
  >>= fun pk_content ->
  Bos.OS.File.read (Fpath.of_string detached_file|>R.get_ok) >>| Cs.of_string
  >>= fun detached_content ->
  Logs.info (fun m -> m "Going to verify that '%S' is a signature on '%S' using key '%S'" detached_file target_file pk_file);

  Openpgp.decode_ascii_armor pk_content >>= fun (Types.Ascii_public_key_block, pk_cs) ->
  Openpgp.parse_packets pk_cs |> R.reword_error (snd)
  >>| List.map (fun (a,b) -> Openpgp.packet_tag_of_packet a , b)
  >>= fun pk_packets ->
  Openpgp.Signature.root_pk_of_packets pk_packets >>= fun (root_pk,_) ->

  Openpgp.decode_ascii_armor detached_content >>= fun (Types.Ascii_signature, sig_cs) ->
  Openpgp.parse_packets sig_cs |> R.reword_error (snd)
  >>= fun ((Openpgp.Signature_type detached_sig , _)::_) ->
  begin match Openpgp.Signature.verify_detached_cb root_pk detached_sig (file_cb target_file) with
    | Ok `Good_signature ->
      Logs.app (fun m -> m "Good signature!") ; Printf.printf "IT WORKS\n"; Ok ()
    | (Error _ as err) ->
      Logs.err (fun m -> m "BAD signature!") ;
      Printf.eprintf "pk:\n%s\nsig:\n%s\n\n%!" (Cs.to_string pk_content) (Cs.to_string detached_content);
      err
  end
  in res |> R.reword_error (fun _ -> `Msg "fuck")

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let docs = Manpage.s_common_options

let pk =
  let doc = "TODO pk doc" in
  Arg.(required & opt (some string) None & info ["pk"] ~docs ~doc)

let signature =
  let doc = "TODO sig doc" in
  Arg.(required & opt (some string) None & info ["signature"] ~docs ~doc)

let target =
  let doc = "TODO target doc" in
  Arg.(required & opt (some string) None & info ["target"] ~docs ~doc)

let help_secs = [
  `S "DESCRIPTION" ;
  `P "$(tname) is a commandline interface to the Ocaml OpenPGP library." ;
  `S Manpage.s_common_options;
  `P "Common options include output verbosity level TODO" ;
  `S Manpage.s_bugs;
  `P "Please report bugs on the issue tracker at <https://github.com/cfcs/ocaml-openpgp/issues>"
]

let setup_log =
  Term.(const setup_log $ Fmt_cli.style_renderer () $ Logs_cli.level ())

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
  Term.(term_result (const do_verify $ setup_log $ pk $ signature $ target)),
  Term.info "verify" ~doc ~sdocs:Manpage.s_common_options ~exits:Term.default_exits ~man

(*in
  Term.(pure cli_main $ pk),
  Term.info "opgp" ~version:"%%VERSION_NUM%%" ~doc ~man
*)

let cmds = [verify_cmd]

let () = Term.(exit @@ eval_choice verify_cmd cmds)
