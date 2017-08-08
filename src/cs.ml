(* Add missing functionality to Cstruct: *)
open Rresult

type t = Cstruct.t
type cstruct_err =
  [ `Cstruct_invalid_argument of string
  | `Cstruct_out_of_memory ]

let wrap_invalid_argument f : ('ok , [> cstruct_err ]) result =
  begin try R.ok @@ f () with
    | Invalid_argument s ->
      Error (`Cstruct_invalid_argument s)
    | Out_of_memory ->
      Error (`Cstruct_out_of_memory)
  end

let wrap_f_buf_offset f buf offset =
  wrap_invalid_argument (fun () -> f buf offset)

let wrap_err errval res =
  res |> R.reword_error (function _ -> errval)

let get_uint8_result buf offset =
  wrap_f_buf_offset Cstruct.get_uint8 buf offset

let sub_result cstr off len =
  wrap_invalid_argument (fun () -> Cstruct.sub cstr off len)

let e_sub e cstr off len =
  wrap_err e (sub_result cstr off len)

let split_result ?(start=0) buf len =
  wrap_invalid_argument (fun () -> Cstruct.split ~start buf len)

let e_split ?(start=0) e buf len =
  wrap_err e (split_result ~start buf len)

let get_char_result buf offset =
  wrap_f_buf_offset Cstruct.get_char buf offset

let e_get_char e buf offset =
  wrap_err e (get_char_result buf offset)

module BE = struct
  let get_uint16 buf offset =
    wrap_f_buf_offset Cstruct.BE.get_uint16 buf offset
  let e_get_uint16 e buf offset =
    wrap_err e (get_uint16 buf offset)

  let get_uint32 buf offset =
    wrap_f_buf_offset Cstruct.BE.get_uint32 buf offset
  let e_get_uint32 e buf offset =
    wrap_err e (get_uint32 buf offset)

  let set_uint16 buf offset (int16 : Usane.Uint16.t) =
    wrap_invalid_argument (fun () ->
        Cstruct.BE.set_uint16 buf offset int16; buf)
  let e_set_uint16 e buf offset int16 =
    wrap_err e (set_uint16 buf offset int16)

  let create_uint16 (int16 : Usane.Uint16.t) =
    let buf = Cstruct.create 2 in
    Cstruct.BE.set_uint16 buf 0 int16 ; buf

  let set_uint32 buf offset (int32 : Usane.Uint32.t) =
    wrap_invalid_argument (fun () ->
        Cstruct.BE.set_uint32 buf offset int32; buf)
  let e_set_uint32 e buf offset int32 =
    wrap_err e (set_uint32 buf offset int32)
  let create_uint32 (int32 : Usane.Uint32.t) =
    let buf = Cstruct.create 4 in
    Cstruct.BE.set_uint32 buf 0 int32 ; buf
end

let of_hex str =
  try R.ok (Hex.to_string (`Hex str) |> Cstruct.of_string) with
  | Invalid_argument _ -> R.error `Invalid_hex

let to_hex cs =
  match Hex.of_string (Cstruct.to_string cs) with
  | `Hex str -> str

let to_string = Cstruct.to_string
let of_string = Cstruct.of_string
let equal = Cstruct.equal
let sub = Cstruct.sub
let len = Cstruct.len (* TODO consider returning Usane.Uint64.t *)
let of_string = Cstruct.of_string
let create = Cstruct.create
let blit = Cstruct.blit
let concat = Cstruct.concat (*TODO wrap exceptions *)
let set_uint8 = Cstruct.set_uint8

let make_uint8 int8 =
  let buf = create 1 in
  set_uint8 buf 0 int8 ; buf

let reverse cs : t =
  (* Zarith hides the function for reading little-endian unsigned integers under
     the name "to_bits".
     In the spirit of wasting time, the author(s) encourages
     kindly doing your own bloody string reversing if you want to
     use Zarith for real-world protocols: *)
  let out_buf = Buffer.create (Cstruct.len cs) in
  (for i = Cstruct.(len cs) - 1 downto 0 do
     Buffer.add_char out_buf Cstruct.(get_char cs i)
   done ;
   Buffer.contents out_buf) |> of_string

(* find char [c] in [b], starting at [offset] and giving up after [max_offset] *)
let index_opt b ?(max_offset) ?(offset=0) c : int option =
  let max = match max_offset with None -> Cstruct.len b | Some m -> (min m Cstruct.(len b)) in
  let rec s = function
    | i when i >= max -> None
    | i when Cstruct.get_char b i = c -> Some i
    | i -> s (i + 1)
  in
  s offset

let e_index e buf ?(max_offset) ?(offset) c =
  (* TODO change buf,c order *)
  R.of_option
    ~none:(fun () -> R.error e)
    (index_opt buf ?max_offset ?offset c)

let index buf ?(max_offset) ?(offset) c : (int, 'error) result =
  e_index `Cstruct_invalid_argument buf ?max_offset ?offset c

(* find substring [needle] in [b] *)
let find b ?(max_offset) ?(offset=0) needle =
  (* TODO label b or needle *)
  let needle_len = Cstruct.len needle
  and b_len = Cstruct.len b in
  let max_offset = match max_offset with
    | None -> max 0 (b_len - needle_len + 1)
    | Some m -> min b_len (m + 1)
  in
  if needle_len = 0 then
    None
  else
    let first_needle = Cstruct.get_char needle 0 in
    let rec next i =
      begin match index_opt ~max_offset ~offset:i b first_needle with
        | None -> None
        | Some c_off ->
          if Cstruct.(equal (sub b c_off needle_len) needle) then
            Some c_off
          else
            next (i + 1)
      end
    in
    next offset

let e_find e b ?max_offset ?offset needle =
  find b ?max_offset ?offset needle
  |> R.of_option ~none:(fun () -> Error e)

let strip_leading_char buf c : t =
  let rec loop offset =
    let max_offset = offset + 1 in
    match index buf ~offset ~max_offset c with
    | Ok _ -> loop max_offset
    | Error _ ->
      e_split `Cstruct_invalid_argument buf offset
      |> R.get_ok
      |> fun (_, tl) -> tl
  in
  loop 0

let strip_trailing_char c buf : t =
  strip_leading_char (reverse buf) c

let split_by_char c ?offset ?max_offset buf : (t*t, 'error) result =
  begin match index_opt ?offset ?max_offset buf c with
    | None -> Ok (Cstruct.create 0 , buf)
    | Some i -> split_result buf i
  end

let equal_string str buf =
  equal buf (of_string str)

let e_equal_string e str buf =
  match equal_string str buf with
  | true -> Ok ()
  | false -> Error e

let e_find_list e buf_list buf : (t,'error) result =
  (* TODO perhaps the "find" name is a bit confusing here. this is "find" in the sense of List.find, not Cs.find*)
  match List.find (equal buf) buf_list with
  | exception Not_found -> Error e
  | member -> Ok member

let e_find_string_list e str_list buf : (string,'error) result=
  e_find_list e (List.map of_string str_list) buf
  >>| to_string

let next_line ?max_length buf : [> `Last_line of t | `Next_tuple of t*t] =
  begin match index_opt ?max_offset:max_length buf '\n' with
    | None -> `Last_line buf
    | Some 0 -> `Next_tuple (Cstruct.create 0 , Cstruct.sub buf 1 (len buf -1))
    | Some n_idx when Cstruct.get_char buf (n_idx-1) = '\r' ->
      `Next_tuple (
        Cstruct.sub buf 0 (n_idx-1),
        Cstruct.sub buf (n_idx+1) (len buf -n_idx-1)
      )
    | Some n_idx ->
      `Next_tuple (
        Cstruct.sub buf 0 n_idx ,
        Cstruct.sub buf (n_idx+1) (len buf - n_idx-1)
      )
  end
