open Rresult

(* TODO set umask when writing files *)
let cs_of_file name =
  Fpath.of_string name >>= Bos.OS.File.read >>| Cs.of_string
  |> R.reword_error (fun _ -> `Msg "Can't open file for reading")

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

let do_verify _ current_time pk_file detached_file target_file
  : (unit, [ `Msg of string ]) Result.result =
  let res =
  cs_of_file pk_file >>= fun pk_content ->
  cs_of_file detached_file >>= fun detached_content ->
  Logs.info
  (fun m -> m "Going to verify that '%S' is a signature on '%S' using key '%S'"
      detached_file target_file pk_file) ;

  Openpgp.decode_public_key_block ~current_time pk_content
  >>= fun (root_pk, extra) ->
  Openpgp.decode_detached_signature detached_content >>= fun detached_sig ->
  Logs.debug (fun m -> m "Parsed sig") ;
  begin match Openpgp.Signature.verify_detached_cb ~current_time root_pk detached_sig (file_cb target_file) with
    | Ok `Good_signature ->
      Logs.app (fun m -> m "Good signature!"); Ok ()
    | (Error _ as err) ->
      Logs.err (fun m -> m "BAD signature!") ;
      Printf.eprintf "pk:\n%s\nsig:\n%s\n\n%!" (Cs.to_string pk_content) (Cs.to_string detached_content);
      err
  end
  in res |> R.reword_error Types.msg_of_error

let do_genkey _ g current_time uid pk_algo =
  (* TODO output private key too ; right now only a transferable public key is serialized *)
  Public_key_packet.generate_new ~current_time ~g pk_algo >>= fun root_key ->
  Openpgp.new_transferable_secret_key ~g ~current_time Types.V4
    root_key [uid] []
  >>= Openpgp.serialize_transferable_secret_key Types.V4
  >>| fun key_cs ->
  let encoded_pk = Openpgp.encode_ascii_armor Types.Ascii_private_key_block key_cs in
  Logs.app (fun m -> m "%s" (Cs.to_string encoded_pk))

let do_list_packets _ target =
  Logs.info (fun m -> m "Listing packets in ascii-armored structure in %s" target) ;
  let res =
  cs_of_file target >>= fun armor_cs ->
  let arm_typ, raw_cs =
    Logs.on_error ~level:Logs.Info
    ~use:(fun _ -> None, armor_cs)
    ~pp:(fun fmt _ -> Fmt.pf fmt "File doesn't look ascii-armored, trying to parse as-is")
    (Openpgp.decode_ascii_armor armor_cs >>| fun (a,c) -> (Some a,c))
  in
  Logs.app (fun m -> m "armor type: %a@.%a"
               (Fmt.option ~none:(Fmt.unit "None")
                 Types.pp_ascii_packet_type) arm_typ
               Cstruct.hexdump_pp raw_cs
           ) ;
  Openpgp.parse_packets raw_cs
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

let do_sign _ g current_time secret_file target_file =
  (
  cs_of_file secret_file >>= Openpgp.decode_secret_key_block >>= fun sk_cs ->
  cs_of_file target_file >>= fun target_content ->
  Openpgp.Signature.root_sk_of_packets ~current_time sk_cs
  >>| Types.log_msg (fun m -> m "parsed secret key") >>= fun (sk,_) ->
  Openpgp.Signature.sign_detached_cs ~g ~current_time sk.root_key
    Types.SHA384 target_content >>= fun sig_t ->
  Openpgp.serialize_packet Types.V4 (Openpgp.Signature_type sig_t)
  >>| Openpgp.encode_ascii_armor Types.Ascii_signature
  >>| Cs.to_string >>= fun encoded ->
  Logs.app (fun m -> m "%s" encoded) ; Ok ()
  )|> R.reword_error Types.msg_of_error

open Cmdliner

let docs = Manpage.s_options
let sdocs = Manpage.s_common_options

let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
                        $ Logs_cli.level ~docs:sdocs ())

let pk =
  let doc = "Path to a file containing a public key" in
  Arg.(required & opt (some string) None & info ["pk"] ~docs ~doc)
let sk =
  let doc = "Path to a file containing a secret/private key" in
  Arg.(required & opt (some string) None & info ["sk";"secret"] ~docs ~doc)
let signature =
  let doc = "Path to a file containing a detached signature" in
  Arg.(required & opt (some string) None & info ["sig";"signature"] ~docs ~doc)

let rng_seed : Nocrypto.Rng.g Cmdliner.Term.t =
  let doc = "Manually supply a hex-encoded seed for the pseudo-random number generator. Used for debugging; SHOULD NOT be used for generating real-world keys" in
  let random_seed seed_hex =
     (Cs.of_hex seed_hex |> R.reword_error
       (fun _ -> "rng-seed: invalid hex string") >>| fun seed ->
     Logs.warn (fun m -> m "PRNG from seed %a" Cstruct.hexdump_pp seed );
     Nocrypto.Rng.generator := Nocrypto.Rng.create ~seed
         (module Nocrypto.Rng.Generators.Fortuna)
     ; !Nocrypto.Rng.generator
     ) |> R.to_presult
  in
  Arg.(value & opt (random_seed, (fun fmt _ -> Format.fprintf fmt "RNG-SEED"))
       !Nocrypto.Rng.generator & info ["rng-seed"] ~docs ~doc)

let override_timestamp : Ptime.t Cmdliner.Term.t =
  let doc = "Manually override the current timestamp (useful for reproducible debugging)" in
  let current_time t =
     (* TODO this can't express the full unix timestamp on 32-bit *)
     let error = `Error ("Unable to parse override-time=" ^ t) in
     match int_of_string t |> Ptime.Span.of_int_s |> Ptime.of_span with
     | exception _ -> error | None -> error
     | Some time -> Logs.warn
        (fun m -> m "Overriding current timestamp, set to %a" Ptime.pp time)
        ; `Ok time
  in
  Arg.(value & opt (current_time, Ptime.pp) (Ptime_clock.now ())
             & info ["override-timestamp"] ~docs ~doc)

let target =
  let doc = "Path to target file" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~docs ~doc)

let uid =
  let doc = "User ID text string (name and/or email, the latter enclosed in <brackets>)" in
  Arg.(required & opt (some string) None & info ["uid"] ~docs ~doc)

let pk_algo : Types.public_key_algorithm Cmdliner.Term.t =
  let doc = "Public key algorithm (either \"RSA\" or \"DSA\")" in
  let convert s = s |> Types.public_key_algorithm_of_string
                  |> function Ok x -> `Ok x | Error (`Msg x) -> `Error x in
  Arg.(value & opt (convert, Types.pp_public_key_algorithm) (Types.DSA)
             & info ["algo";"pk-algo"] ~docs ~doc)

let secret =
    let doc = "Filename to write the new secret key to" in
    Arg.(required & opt (some string) None & info ["secret"] ~docs ~doc)
  and public =
    let doc = "Filename to write the new public key to" in
    Arg.(required & opt (some string) None & info ["public"] ~docs ~doc)

let genkey_cmd =
  let doc = "Generate a new keypair" in
  let man = [
    `S "USAGE" ;
    `P "$(tname) --uid 'My name'" ;
    ]
  in
  Term.(term_result (const do_genkey $ setup_log $ rng_seed $ override_timestamp
                                     $ uid $ pk_algo)),
  Term.info "genkey" ~doc ~sdocs ~exits:Term.default_exits ~man

let verify_cmd =
  let doc = "Verify a detached signature on a file" in
  let man = [
    `S Manpage.s_description ;
    `P "Verify that the [signature] is a signature on [target] issued by [pk].";
    `S "USAGE" ;
    `P "$(tname) --pk public-key.asc --sig detached-signature.asc FILE" ;
    ]
  in
  Term.(term_result (const do_verify $ setup_log $ override_timestamp $ pk
                                     $ signature $ target)),
  Term.info "verify" ~doc ~sdocs
    ~exits:Term.default_exits ~man
    ~man_xrefs:[`Cmd "sign"]

let list_packets_cmd =
  let doc = "Pretty-print the packets contained in FILE" in
  let man = [] in
  Term.(term_result (const do_list_packets $ setup_log $ target)),
  Term.info "list-packets" ~doc ~sdocs
            ~exits:Term.default_exits ~man

let sign_cmd =
  let doc = "Produce a detached signature on a file" in
  let man = [
    `S Manpage.s_description ;
    `P ( "Takes a secret key and a target file as arguments and outputs an "
         ^ "ASCII-armored signature that can be used with the corresponding "
         ^ "public key to verify the authenticity of the target file.") ;
    `P "This is similar to GnuPG's --detach-sign" ;
    `S "USAGE" ;
    `P "$(mname) $(tname) --sk secret-key.asc FILE_TO_SIGN" ;
    ]
  in
  Term.(term_result (const do_sign $ setup_log $ rng_seed $ override_timestamp
                                   $ sk $ target)),
  Term.info "sign" ~doc ~exits:Term.default_exits ~man ~sdocs
                   ~man_xrefs:[`Cmd "verify"]

let help_cmd =
  let doc = "$(tname) is a commandline interface to the Ocaml OpenPGP library." in
  let man =
[ `S "EXAMPLES" ;
  `P "# $(mname) genkey --uid 'Abbot Hoffman' > abbie.priv" ;
  `P "# $(mname) sign --sk abbie.priv MKULTRA.DOC > MKULTRA.DOC.asc" ;
  `P "# gpg2 --import abbie.priv ; gpg --export 'Abbot Hoffman' > abbie.pub";
  `P "gpg: key 6EF4BA2AC8028106: public key \"Abbot Hoffman\" imported" ;
  `P "gpg: key 6EF4BA2AC8028106: secret key imported" ;
  `P "gpg: Total number processed: 1" ;
  `P "gpg:               imported: 1" ;
  `P "gpg:       secret keys read: 1" ;
  `P "gpg:   secret keys imported: 1" ;
  `P "# $(mname) verify --sig MKULTRA.DOC.asc --pk abbie.pub  MKULTRA.DOC" ;
  `P "opgp: [ERROR] Failed decoding ASCII armor ASCII public key block," ;
  `P "              parsing as raw instead" ;
  `P "Good signature!" ;
  `P "# echo $?" ;
  `P "0" ;
  `S Manpage.s_bugs;
  `P ( "Please report bugs on the issue tracker at "
     ^ "<https://github.com/cfcs/ocaml-openpgp/issues>") ]
  in
  let help _ = `Help (`Pager, None) in
  Term.(ret (const help $ setup_log)),
  Term.info "opgp" ~version:(Manpage.escape "%%VERSION_NUM%%") ~man ~doc ~sdocs


let cmds = [verify_cmd ; genkey_cmd; list_packets_cmd; sign_cmd]

let () =
  Nocrypto_entropy_unix.initialize () ;
  Term.(exit @@ eval_choice help_cmd cmds)
