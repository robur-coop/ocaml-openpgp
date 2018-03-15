(** Literal Data Packet (Tag 11) *)

open Rresult

type data_format =
  | Literal_binary
  | Literal_text_with_crlf
  (** - Text data is stored with <CR><LF> text endings (i.e., network-
        normal line endings).  These should be converted to native line
        endings by the receiving software.*)

val pp_data_format : Format.formatter -> data_format -> unit

type streaming
type in_memory

type 'kind parser

type final_state =  private { format : data_format (** text or binary*);
                              filename : string (* peer's suggested filename**);
                              time : string (** The unspecified time field.*); }

type 'kind t = private

  (** doesn't store the actual packet data: *)
  |  Streaming_t : final_state -> streaming t

  (** accumulates data as a list of strings inside [t]: *)
  |  In_memory_t : final_state * string list -> in_memory t

val in_memory_parser : total_len:int64 -> (in_memory parser, [> R.msg] )result
(** [in_memory_parser ~total_len] is a parser that will read up to [total_len]
    bytes. It can be used with [parse_streaming].
    The parser stores the accumulated packet in its state, which is useful for
    small files when you don't want to bother with buffer management.*)

val streaming_parser : total_len:int64 -> (streaming parser, [> R.msg] )result
(** [streaming_parser ~total_len] is a parser that will read up to [total_len]
    bytes. It can be used with [parse_streaming].
    The parser will cause [parse_streaming] to return each block of packet body
    directly, which is useful for reading large files that do not fit in memory.
*)


val parse_streaming : 'kind parser -> ([> R.msg ] as 'err) Cs.R.rt ->
  ('kind parser * string option, 'err)result
(** [parse_streaming parser src] is a tuple of
    [(next_parser_state * packet_body)], reading from the [src].
    Different [src] can be used across repeated calls to [parse_streaming],
    enabling you to page out the memory occupied by a [src] once it has been
    depleted.
*)

val parse : ?offset:int -> Cs.t -> (in_memory t, [> R.msg ]) result
(** [parse ?offset src] is an [in_memory t] starting at optional
    [?offset] (default: 0) of [src].*)

val serialize : 'kind t -> Cs.t
(** [serialize t] is the serialized header for the Literal Data Packet [t].
    If [t] is an [in_memory t], the stored body will also be serialized.
    If [t] is a [streaming t], you must use [serialize] to obtain the header
    yourself, and fill in the body yourself.
*)
