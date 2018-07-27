(* https://tools.ietf.org/html/rfc4880#section-5.6 *)

(* This implementation is pretty wasteful in terms of memory consumption,
   should be revised at some point... TODO *)

open Rresult

let decompress_common input_ro =
  (* copy-pasted from my imagelib stub *)
  let len = String.length input_ro in
  let inputpos = ref 0 in
  let input_temp, output_temp = Bytes.(create 0xFFFF, create 0xFFFF) in
  let final_output = Buffer.create (len / 3) in (* approx avg rate? *)

  let refill (strbuf:Bytes.t) : int =
    let remaining = len - !inputpos in
    let tocopy = min 0xFFFF remaining in
    Bytes.blit_string input_ro !inputpos strbuf 0 tocopy;
    inputpos := !inputpos + tocopy;
    tocopy
  in

  let flush strbuf len =
    Buffer.add_subbytes final_output strbuf 0 len ;
    0xFFFF
  in

  let open Decompress in
  let window = Window.create ~proof:B.proof_bytes in
  input_temp, output_temp, refill, flush, window, final_output

let decompress_zlib input_ro =
  let input_temp, output_temp, refill, flush, window, final_output =
    decompress_common input_ro in
  let open Decompress in
  Zlib_inflate.bytes input_temp output_temp
    refill flush Zlib_inflate.(default window)
  |> R.reword_error (fun _ -> R.msg "ZLIB inflation failed")
  >>| fun _ -> Buffer.contents final_output

let decompress_zip input_ro =
  let input_temp, output_temp, refill, flush, window, final_output =
    decompress_common input_ro in
  let open Decompress in
  RFC1951_inflate.bytes input_temp output_temp
    refill flush RFC1951_inflate.(default window)
  |> R.reword_error (fun _ -> R.msg "RFC1951:ZIP inflation failed")
  >>| fun _ -> Buffer.contents final_output


let parse cs_r : (string, [> R.msg] )result =
  (* - One octet that gives the algorithm used to compress the packet. *)
  Cs.R.char cs_r >>| Types.compression_algorithm_of_char >>= fun algo ->
  Cs.R.(string cs_r @@ len cs_r) >>= fun remaining ->
  Logs.debug (fun m -> m "Decompressing %a packet of length %d"
                 Types.pp_compression_algorithm algo
                 (String.length remaining) );
  match algo with
  | Types.ZLIB -> decompress_zlib remaining
  | Types.ZIP  -> decompress_zip remaining
  | unknown -> R.error_msgf "Unimplemented compression algorithm: %a"
                 Types.pp_compression_algorithm unknown
