open Rresult

let cs_of_fpath fp =
  Bos.OS.File.read fp >>| Cs.of_string
  |> R.reword_error (fun _ ->
      `Msg (Format.sprintf "Can't open %S for reading" @@ Fpath.to_string fp))

let cs_of_file name =
  (* TODO this is duplicated in opgp.ml ... *)
  Fpath.of_string name >>= cs_of_fpath

let verify_git_signature target_filename =
  let current_time = Ptime_clock.now () in
  let rec read_until_two_newlines = function
    | (""::""::_) as acc -> acc
    | acc -> read_until_two_newlines
               (begin try input_line stdin with End_of_file -> "" end::acc)
  in
  ( read_until_two_newlines []
    |> List.rev
    |> String.concat "\n"
    |> Cs.of_string
    |> Openpgp.decode_detached_signature
  ) >>= fun detached_sig ->

  ( Bos.OS.Dir.user () >>= fun homedir ->
    (* TODO this only works for a single public key, need to restructure
       Openpgp.root_pk_of_packets to return the unconsumed packets,
       and provide a helper function for looping it to retrieve PKs from a
       GnuPGv1-compatible pubring.gpg: *)
    cs_of_fpath (Fpath.add_seg homedir "opgp-git.asc")
    >>= Openpgp.decode_public_key_block ~current_time
    >>| fst ) >>= fun root_pk ->

  cs_of_file target_filename >>= fun file_to_check ->
  Openpgp.Signature.verify_detached_cs
    ~current_time
    root_pk
    detached_sig
    file_to_check

let () =
  Fmt_tty.setup_std_outputs () ;
  Logs.set_reporter (Logs_fmt.reporter ());
  begin match Sys.argv.(0) with exception _ -> ()
    | comm ->
      (* normalize argv[0] aka comm: *)
      Sys.argv.(0) <- (match Filename.basename comm with
          | "opgp-git.native"
          | "opgp-git.byte" -> "opgp-git"
          | whatever -> whatever)
  end ;
  begin match Sys.argv with
    | [| "opgp-git"; "--verify"; filename; "-" |] ->
      (* verify that [filename] is signed by the detached signature read
         on stdin, using some magical key database for looking up the PK.*)
      begin match verify_git_signature filename with
        | Ok _ -> Pervasives.exit 0
        | Error `Msg err ->
          Logs.err (fun m -> m "Verification failed: @[<v>%s@]" err)
      end

    | [| "opgp-git"; "-bsau"; keygrip |] ->
      (* detached armored signature signed by [keygrip]'s secret key *)
      Logs.err (fun m ->
          m "TODO signature generation not implemented. :-(@ \
             but if it was, it would have used %S to sign."
            keygrip )

    | [| "opgp-git"; "--help" |] ->
      Printf.eprintf
        "TODO help! See README.md or open an issue on the Github issue tracker.\n"

    | [| "opgp-git"; "--version" |] ->
      Printf.eprintf
        "opgp-git version %%VERSION%%\n\
         OCaml version: %s\n\
         OS-type: %s\n\
         int-size: %d\tbig-endian: %b\tbackend-type: %s\n\
         Max string length: %d\n\
         Runtime: %s // %s\n"
        Sys.ocaml_version
        Sys.os_type
        Sys.int_size
        Sys.big_endian
        Sys.(match backend_type with
            | Native -> "native"
            | Bytecode -> "bytecode"
            | Other str -> str )
        Sys.max_string_length
        (Sys.runtime_variant ())
        (Sys.runtime_parameters ())

    | [| "opgp-git" |] | [| "opgp-git"; _ |] ->
      Logs.err (fun m ->
          m "Invalid set of parameters passed to opgp-git.@ \
             See opgp-git --help" )

    | _ ->
      Logs.err (fun m ->
          m "opgp-git must be called with \"opgp-git\" in argv[0].@ \
             Did you execute this program using a symbolic link %s?"
            Sys.argv.(0) )
  end ;
  Pervasives.flush_all () ;
  (* default to exiting with error: *)
  Pervasives.exit 1
