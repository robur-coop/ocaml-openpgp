open Rresult

(* TODO set umask when writing files *)

let cs_of_file name =
  Fpath.of_string name >>= Bos.OS.File.read >>| Cs.of_string
  |> R.reword_error (fun _ -> `Malformed) (*TODO fix error msg*)

let file_cb filename : unit -> ('a,'b)result =
  (* TODO read file in chunks *)
  let content = ref (fun () -> cs_of_file filename >>| (fun cs -> Some cs)) in
  (fun () ->
     let x = !content () in
     content := (fun () -> Ok None); x
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

let do_verify _ pk_file detached_file target_file : (unit, [ `Msg of string ]) Result.result =
  let res =
  cs_of_file pk_file >>= fun pk_content ->
  cs_of_file detached_file >>= fun detached_content ->
  Logs.info (fun m -> m "Going to verify that '%S' is a signature on '%S' using key '%S'" detached_file target_file pk_file);

  Openpgp.decode_ascii_armor pk_content
  >>= (function (Types.Ascii_public_key_block, pk_cs) -> Ok pk_cs
              | _ -> Error `Invalid_packet)
  >>= fun pk_cs ->
  Openpgp.parse_packets pk_cs |> R.reword_error (snd)
  >>| List.map (fun (a,b) -> Openpgp.packet_tag_of_packet a , b)
  >>= fun pk_packets ->
  let current_time = Ptime_clock.now () in
  Openpgp.Signature.root_pk_of_packets ~current_time pk_packets >>= fun (root_pk,_) ->

  Openpgp.decode_ascii_armor detached_content
  >>= (function (Types.Ascii_signature, sig_cs) -> Ok sig_cs | _ -> Error `Invalid_packet)
  >>= fun sig_cs ->
  Openpgp.parse_packets sig_cs |> R.reword_error (snd)
  >>= (function
      |((Openpgp.Signature_type detached_sig , _)::_) -> Ok detached_sig
      | _ -> Error `Invalid_packet
    ) >>= fun detached_sig ->
  begin match Openpgp.Signature.verify_detached_cb ~current_time root_pk detached_sig (file_cb target_file) with
    | Ok `Good_signature ->
      Logs.app (fun m -> m "Good signature!") ; Printf.printf "IT WORKS\n"; Ok ()
    | (Error _ as err) ->
      Logs.err (fun m -> m "BAD signature!") ;
      Printf.eprintf "pk:\n%s\nsig:\n%s\n\n%!" (Cs.to_string pk_content) (Cs.to_string detached_content);
      err
  end
  in res |> R.reword_error Types.msg_of_error


let do_genkey _ uid =
  (* TODO output private key too ; right now only a transferable public key is serialized *)
  let current_time = Ptime_clock.now () in
  let g = !Nocrypto.Rng.generator in
  let res =
  Public_key_packet.generate_new ~current_time ~g Types.DSA >>= fun root_key ->
  Openpgp.new_transferable_public_key ~g ~current_time Types.V4
    root_key [uid] []
  >>= Openpgp.serialize_transferable_public_key
  >>= fun key_cs ->
  let encoded_pk = Openpgp.encode_ascii_armor Types.Ascii_public_key_block key_cs in
  Logs.app (fun m -> m "%s" (Cs.to_string encoded_pk)) ;
  Ok ()
  in res |> R.reword_error Types.msg_of_error

let do_list_packets _ target =
  Logs.info (fun m -> m "Listing packets in ascii-armored structure in %s" target) ;
  let res =
  cs_of_file target >>= fun armor_cs ->
  let arm_typ, raw_cs =
    Logs.on_error ~level:Logs.Info
    ~use:(fun _ -> None, armor_cs)
    ~pp:(fun fmt e -> Fmt.pf fmt "File doesn't look ascii-armored, trying to parse as-is")
    (Openpgp.decode_ascii_armor armor_cs >>| fun (a,c) -> (Some a,c))
  in
  Logs.app (fun m -> m "armor type: %a@.%a"
               (Fmt.option ~none:(Fmt.unit "None")
                 Types.pp_ascii_packet_type) arm_typ
               Cstruct.hexdump_pp raw_cs
           ) ;
  Openpgp.parse_packets raw_cs |> R.reword_error (snd)
  >>= fun pkts_tuple ->
  let () = Logs.app (fun m -> m "Packets:@.|  %a"
               (fun fmt -> Fmt.pf fmt "%a"
                 Fmt.(list ~sep:(unit "@.|  ")
                      (vbox @@ pair ~sep:(unit "@,Hexdump: ")
                         Openpgp.pp_packet Cstruct.hexdump_pp ))
               ) pkts_tuple
  ) in
  Ok ()
  in
  res |> R.reword_error Types.msg_of_error

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
  let doc = "Target file to be signed / verified" in
  Arg.(required & opt (some string) None & info ["target"] ~docs ~doc)

let uid =
  let doc = "User ID text string (name and/or email, the latter enclosed in <brackets>)" in
  Arg.(required & opt (some string) None & info ["uid"] ~docs ~doc)

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

let genkey_cmd =
  let doc = "TODO genkey cmd doc" in
  let man = [
    `S Manpage.s_description ;
    `P "Generate a new key pair" ;
    `S "USAGE" ;
    `P "$(tname)" ; (* TODO optionally output to file *)
    `Blocks help_secs ]
  in
  let secret =
    let doc = "Filename to write the new secret key to" in
    Arg.(required & opt (some string) None & info ["secret"] ~docs ~doc)
  and public =
    let doc = "Filename to write the new public key to" in
    Arg.(required & opt (some string) None & info ["public"] ~docs ~doc)
  in
  Term.(term_result (const do_genkey $ setup_log $ uid )),
  Term.info "genkey" ~doc ~sdocs:Manpage.s_common_options ~exits:Term.default_exits ~man

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

let list_packets_cmd =
  let doc = "Pretty-print the packets contained in the [--target] file" in
  let man = [] in
  Term.(term_result (const do_list_packets $ setup_log $ target)),
  Term.info "list-packets" ~doc ~sdocs:Manpage.s_common_options ~exits:Term.default_exits ~man

(*in
  Term.(pure cli_main $ pk),
  Term.info "opgp" ~version:"%%VERSION_NUM%%" ~doc ~man
*)

let cmds = [verify_cmd ; genkey_cmd; list_packets_cmd]

let () =
  Nocrypto_entropy_unix.initialize () ;
  Term.(exit @@ eval_choice verify_cmd cmds)
