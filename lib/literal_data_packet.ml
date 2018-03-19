type state_machine =
  | Format (* waiting for one byte format *)
  | Filename_len (* waiting for one byte filename len *)
  | Filename of string list * int (* acc in reverse order * remaining bytes*)
  | Time of string list * int (* remaining bytes of the ignored (by me) "time"*)
  | Literal_data (* this is returned in streaming fashion, not stored in state*)

let pp_state_machine fmt state =
  Fmt.pf fmt "(state: %s)" @@ match state with
  | Format -> "Format"
  | Filename_len -> "Filename_len"
  | Filename (_acc, remaining) -> "Filename (" ^ string_of_int remaining ^")"
  | Time (_acc, remaining) -> "Time (" ^ string_of_int remaining ^ ")"
  | Literal_data -> "Literal_data"

type data_format =
  | Literal_binary
  | Literal_text_with_crlf
  (* - Text data is stored with <CR><LF> text endings (i.e., network-
       normal line endings).  These should be converted to native line
       endings by the receiving software.*)

let pp_data_format fmt v =
  Fmt.pf fmt "data format: %s" @@ match v with
  | Literal_binary -> "Binary"
  | Literal_text_with_crlf -> "Text"

type 'error parser_state =
  { remaining : int64 ;
    state : state_machine ;
    format : data_format option ;
    filename : string option ;
    time : string option ;
  }

type streaming = [ `streaming ]
type in_memory = [ `in_memory ]

type 'kind parser =
  | Streaming_p : 'error parser_state -> streaming parser
  | In_memory_p : 'error parser_state -> in_memory parser
  (*  constraint 'kind = [< streaming | in_memory]*)

let pp_parser (type kind) fmt (v:kind parser) =
  begin match v with
    | Streaming_p { remaining ; time ; filename ; format ; state} ->
      "streaming" , remaining, time, filename, format, state
    | In_memory_p { remaining ; time ; filename ; format ; state} ->
      "in-memory" , remaining, time, filename, format, state
  end |> fun (s, remaining, time, filename, format, state) ->
  Fmt.pf fmt "(@[<v>parser: %s@ (remaining %Ld)@ (time: %a)@ (filename: %a)@ \
              (format: %a) %a @])" s remaining
    Fmt.(option string) time
    Fmt.(option string) filename
    Fmt.(option pp_data_format) format
    pp_state_machine state

type final_state =  { format : data_format ;
                      filename : string ;
                      time : string ;
                    }

type 'kind t =
  (* doesn't store the actual packet data: *)
  |  Streaming_t : final_state -> streaming t
  (* accumulates data as a list of strings: *)
  |  In_memory_t : final_state * string list -> in_memory t
  (*  constraint 'kind = [< streaming | in_memory ]*)

let pp_final_state fmt { format ; filename ; time} =
  Fmt.pf fmt "{ @[<v>format: %a@ \
              filename: %S@ \
              time: %S@ @]}" pp_data_format format filename time

let pp fmt (type kind) (v : kind t) =
  Fmt.pf fmt "Literal Data Packet: %a" pp_final_state
  @@ match v with
  | In_memory_t (s,_) -> s
  | Streaming_t s -> s

open Rresult

let parser_create ~total_len
  : ('a, [> R.msg] )result =
  let (+) = Int64.add in
  if total_len >= (1_L + 1_L + 4_L) then
    let empty = { remaining = total_len ;
                  state = Format ;
                  format = None ;
                  filename = None ;
                  time = None ; } in
    Ok empty
  else
    R.error_msgf "Tried to parse literal data packet of total size %Ld \
                  (smaller than minimum length which is six bytes)" total_len

let streaming_parser ~total_len : (streaming parser, [> R.msg] ) result =
  parser_create ~total_len >>| fun p -> Streaming_p p

let in_memory_parser ~total_len : (in_memory parser, [> R.msg] ) result =
  parser_create ~total_len >>| fun p -> In_memory_p p

let parse_state
    ~chunk_size ({ remaining ; state; format = _ ;
                   filename = _; time = _ } as sm) cs_r =
  (* we read chunks up to [chunk_size] bytes: *)
  let max_read = min chunk_size
    (* remaining may be > 2G, but we deal with Cs.R.rt's that are smaller: *)
    @@ min (Cs.R.len cs_r) @@ abs @@ Int64.to_int remaining  in
  let consume len sm =
    { sm with remaining = Int64.(sub sm.remaining @@ of_int len ); }
  in
  match state with
  | Format when max_read >= 1 ->
    (* - A one-octet field that describes how the data is formatted *)
    (*   If it is a 'b' (0x62), then the Literal packet contains binary data.
       If it is a 't' (0x74), then it contains text data, and thus may need
       line ends converted to local form, or other text-mode changes.  The
       tag 'u' (0x75) means the same as 't', but also indicates that
       implementation believes that the literal data contains UTF-8 text.*)
    Cs.R.char cs_r >>= begin function
    | 'b' -> Ok Literal_binary
    | 't' -> Ok Literal_text_with_crlf
    | c   -> R.error_msgf "Invalid Literal Data Packet format: %C" c
    end >>| fun format ->
    consume 1 {sm with format = Some format ; state = Filename_len}, None

  | Filename_len when max_read >= 1 ->
    (* - File name as a string (one-octet length, followed by a file
         name).  This may be a zero-length string.*)
    Cs.R.uint8 cs_r >>| fun filename_len ->
    consume 1 {sm with state = Filename ([],filename_len) }, None

  | Filename (acc, 0) ->
    (*   If the special name "_CONSOLE" is used, the message is considered to
         be "for your eyes only".  This advises that the message data is
         unusually sensitive, and the receiving program should process it more
         carefully, perhaps avoiding storing the received data to disk, for
         example.*)
    (* TODO consider if we should implement that.
       For now leave it to the application.*)
    Ok ({sm with state = Time ([], 4);
                filename = Some (String.concat "" @@ List.rev acc); }, None)

  | Filename (acc, n) ->
    let consumed = min n max_read in
    Cs.R.string cs_r consumed >>| fun data ->
    consume consumed {sm with state = Filename (data::acc, n-consumed); }, None

  | Time (acc, 0) ->
    Ok ({sm with state = Literal_data ;
                time = Some (String.concat "" @@ List.rev acc); }, None)

  | Time (acc, n) ->
    (* - A four-octet number that indicates a date associated with the
         literal data.  Commonly, the date might be the modification date
         of a file, or the time the packet was created, or a zero that
         indicates no specific time.*)
    (* ^-- While that is completely useless, we store it so we can hash
           the packet.*)
    let consumed = (min n @@ min max_read @@ Cs.R.len cs_r)in
    Cs.R.string cs_r consumed >>| fun data ->
    consume consumed
      { sm with state = Time (data::acc, n-consumed); }, None

  | Literal_data when max_read = 0 -> (* wait for more, or terminate*)
    Ok (sm, None)

  | Literal_data ->
    (* - The remainder of the packet is literal data: *)
    Cs.R.string cs_r max_read >>| fun data ->
    consume max_read sm, Some data

  | Format
  | Filename_len -> (* when Cs.R.len cs_r = 0, we wait for more input. *)
    Ok (sm, None)

let parse_streaming (type kind) (parser: kind parser) cs_r
  : (kind parser * string option, [> R.msg]) result =
  match parser with
  | Streaming_p state_machine ->
    parse_state ~chunk_size:8100 state_machine cs_r >>| fun (sm, data) ->
    (Streaming_p sm), data
  | In_memory_p state_machine ->
    parse_state ~chunk_size:8100 state_machine cs_r >>| fun (sm, data) ->
    (In_memory_p sm), data

let parse ?offset cs : (in_memory t, [> R.msg ]) result =
  let cs_r =
    Cs.R.of_cs (R.msg "Failed to parse literal data packet") ?offset cs in
  let rec loop acc sm =
    parse_streaming sm cs_r >>= function
    | (sm, Some data) -> loop (data::acc) sm
    | ( In_memory_p (
        { state = (Format | Filename_len | Filename _ | Time _ ) ; _ }
      | { filename = None ; _ }
      | { time = None ; _ }
      | { format = None ; _}
      ) as new_sm) , None -> loop acc new_sm
    | (In_memory_p { state = Literal_data ; remaining = 0_L; format =_ ;
                     filename = _ ;  time = _ } as sm, None) ->
      Ok (sm, List.rev acc)
    | sm, None -> loop acc sm
  in
  parser_create ~total_len:(Cs.R.len cs_r |> Int64.of_int) >>= fun sm ->
  loop [] (In_memory_p sm) >>= function
  | In_memory_p { remaining = 0_L ;
                  format = Some format ;
                  filename = Some filename ;
                  time = Some time ;
                  state = Literal_data ;
                }, data ->
    Ok (In_memory_t ({ format ; filename ; time ;}, data))
  | (parser, acc) ->
    R.error_msgf "Failed decoding literal packet: (%a) (acc: %a)"
      pp_parser parser
      Fmt.(list string) acc

let serialize_t (type kind) (t: kind t) =
  let { format ; filename ; time } = match t with
    | In_memory_t (a,_)-> a
    | Streaming_t a -> a
  in
  String.concat ""
    [ (match format with Literal_binary -> "b"
                       | Literal_text_with_crlf -> "t") ;
      String.make 1 (String.length filename |> Char.chr) ;
      filename ;
      time ;
    ]

let serialize (type kind) (t: kind t) =
  let state = serialize_t t in
  begin match t with | Streaming_t _ -> state
               | In_memory_t (_, saved) -> String.concat "" (state::saved)
  end |> Cs.of_string
