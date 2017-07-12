open QCheck
open QCheck.Test
open Rresult
open OUnit2
open Types
open Openpgp

let test_pkp_cstruct = Cs.of_string
"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQMuBFkOBx0RCADSbRim2QNp+1nZKePQ7Oc8TmYXSdP/789Uitw7KVG4vpWsQ49k\nP/GqCbWcCGVoiMg3UVVCBR6KxEvc33TMfsicoLN8ucVXF6RXwFcyBIh0aFRBhNvI\nTj1jvGmOP9QGCYUUXUZ92AXw9LPtK13mC0DjUlPcQ2rpzw5+MZItU1GcJOI1bSyF\nc11gHGm16zs999KCr3ufK0cHvMTbnHPYNPzcj2QVaKiRjp0BpGAtzTQZ29igW00r\nQZqhz38bBvsSU1HdLl8SqiyxGv/+jvnS2HYsWjJBD8oFn4+4Qol3YBdWZBZbJhQ4\nPMxdUQXdGUIjXKLUguwvnqiA7UVsSHverq9zAQDcpJDs4KZIDSKUJR97yNMjf9so\n6HuU4y6yitSrDIKJPQf6Al3ndlyVtfmXsZz/1zDQ1qCsYauQjE6fO2XqOrkOtzz+\n8KP3sizP/CzADJO8YUSJKT+I29ZtQ5zlnDILpv9fWhgOiw9XhaC0BOsC+8DQxZCB\nw6kodbUWk03IFGiqAPNNKMFZZHb9B4sC8+G2c/TYnzMJGuPcf/tZaUqi73CThgqk\nCSiAsSWV3D+OaJpCeTsPa4lzpV5tEZjaZbejXUhgvapkVmRsLGvlDSzuu0srKyXu\n17VYwkjI8YSTfMHxrFJQoAzeRd0KmKkwofi/4HISwGMBq6KV0Ri5Falyk4lmC3LV\nPLR8VEzB4NTihzRWxeimfGcqzodwjc7d4sLSFXVnFQgAxt1Aet64bLtiH8UqdfNx\nvC7tkNW3CoPWm1qhCe2kYzeEw7nrpATrHZb4BeGCCGuJN+a10P5vbQo6xTgaTjbX\nlwGcuWAN3JPLCnYBzIgaXawr2uaLUj8ngZFwo5+z2VlzSKbP68L/Te9sJA0kR5uu\nIGBFvtt1f36adWzN9drP+ik6vMq6i2v8W0NIk4Ox3YKvkzxFyNSxG0e97UCjZzkV\nxdehIja5kegD0LpCwxUByisOBm0ZAvUyju1o1PYsTkdIq1+HMuKNdcEvqxgYXRVV\nTRyJWRE3c/s6SapkyFnUgQ8rpFJB9szksLcVihSO2TlycQltK/Kd/cMx01as7ghJ\nVrQFeWVsbG+IewQTEQgAIwUCWQ4HHQIbAwcLCQgHAwIBBhUIAgkKCwQWAgMBAh4B\nAheAAAoJEGgDEFdHybWaw+8A/0qmk8I3NV0HDKqmcYyOZLfcQvUbcbd1LUNWBM7A\n2lUyAP9PWi8vXliL2D5oXAD4HR3lyfSbd4+sI9u5gmOXG1CNZQ==\n=WdLf\n-----END PGP PUBLIC KEY BLOCK-----"

let asciiz =
  (* generate strings without nullbytes *)
  let ig = QCheck.Gen.int_range 1 0xff in
  let cg = QCheck.Gen.map (char_of_int) ig in
  QCheck.Gen.string ~gen:cg |> QCheck.make

let test_unpack_ascii_armor _ =
  check_exn @@ QCheck.Test.make ~count:1
    ~name:"unpack ascii armor"
    (triple string string small_int)
    @@ (fun (username, hostname, port) ->
      begin match Openpgp.decode_ascii_armor test_pkp_cstruct with
      | Ok x -> x = x
      | Error `Invalid -> failwith "invalid"
      | Error `Invalid_crc24 -> failwith "invalid crc24"
      | Error `Missing_crc24 -> failwith "missing crc24"
      end
      );
;;

let test_self_check _ =
  print_newline () ;
  (Openpgp.decode_ascii_armor test_pkp_cstruct
   >>= fun (ascii_packet_type , unasciied) ->
   Openpgp.next_packet unasciied
   >>= fun (Some (packet_tag, pkt_body, next_packet)) ->
   Ok (packet_tag, pkt_body, next_packet)
  )|>
  begin function
    | Error (`Incomplete_packet) -> failwith "self_check need more bytes"
    | Error (`Invalid_packet) -> failwith "self_check: invalid packet"
    | Error `Incomplete_packet -> failwith "incomplete packet"
  | Error _ -> failwith "self_check ascii armor"
  | Ok (_, pkt_body, next) ->
    (Public_key_packet.parse_packet pkt_body >>= fun (`DSA pub) ->
    R.ok @@ Printf.printf "\nPkt len:%d - got a DSA key: %s\n"
      Cstruct.(len pkt_body) Public_key_packet.(v4_key_id pkt_body)
    );()
  end

let suite = [
  "unpack_ascii_armor" >:: test_unpack_ascii_armor;
  "self_check" >:: test_self_check;
  ]
