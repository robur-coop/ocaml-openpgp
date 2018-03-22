(* https://tools.ietf.org/html/rfc4880#section-5.6 *)

(* This implementation is pretty wasteful in terms of memory consumption,
   should be revised at some point... TODO *)

open Rresult

let decompress_zlib input_ro =
  (* copy-pasted from my imagelib stub *)
  let inputstr = Bytes.of_string input_ro in
  let len = Bytes.length inputstr in
  let inputpos = ref 0 in
  let input_temp, output_temp = Bytes.(create 0xFFFF, create 0xFFFF) in
  let final_output = Buffer.create (len / 3) in (* approx avg rate? *)

  let refill (strbuf:Bytes.t) : int =
    let remaining = len - !inputpos in
    let tocopy = min 0xFFFF remaining in
    Bytes.blit inputstr !inputpos strbuf 0 tocopy;
    inputpos := !inputpos + tocopy;
    tocopy
  in

  let flush strbuf len =
    Buffer.add_subbytes final_output strbuf 0 len ;
    0xFFFF
  in

  let open Decompress in
  let window = Window.create ~proof:B.proof_bytes in

  Inflate.bytes input_temp output_temp
    refill flush Inflate.(default window)
  |> R.reword_error (fun _ -> R.msg "ZLIB inflation failed")
  >>| fun _ -> Buffer.contents final_output

let parse cs_r : (string, [> R.msg] )result =
  (* - One octet that gives the algorithm used to compress the packet. *)
  Cs.R.char cs_r >>| Types.compression_algorithm_of_char >>= fun algo ->
  Cs.R.(string cs_r @@ len cs_r) >>= fun remaining ->
  match algo with
  | Types.ZLIB -> decompress_zlib remaining
  | unknown -> R.error_msgf "Unknown compression algorithm: %a"
                 Types.pp_compression_algorithm unknown
