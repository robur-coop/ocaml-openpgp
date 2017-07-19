open QCheck
open QCheck.Test
open Rresult
open OUnit2
open Public_key_packet
open Openpgp

let test_pkp_cstruct = Cs.of_string
"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQMuBFkOBx0RCADSbRim2QNp+1nZKePQ7Oc8TmYXSdP/789Uitw7KVG4vpWsQ49k\nP/GqCbWcCGVoiMg3UVVCBR6KxEvc33TMfsicoLN8ucVXF6RXwFcyBIh0aFRBhNvI\nTj1jvGmOP9QGCYUUXUZ92AXw9LPtK13mC0DjUlPcQ2rpzw5+MZItU1GcJOI1bSyF\nc11gHGm16zs999KCr3ufK0cHvMTbnHPYNPzcj2QVaKiRjp0BpGAtzTQZ29igW00r\nQZqhz38bBvsSU1HdLl8SqiyxGv/+jvnS2HYsWjJBD8oFn4+4Qol3YBdWZBZbJhQ4\nPMxdUQXdGUIjXKLUguwvnqiA7UVsSHverq9zAQDcpJDs4KZIDSKUJR97yNMjf9so\n6HuU4y6yitSrDIKJPQf6Al3ndlyVtfmXsZz/1zDQ1qCsYauQjE6fO2XqOrkOtzz+\n8KP3sizP/CzADJO8YUSJKT+I29ZtQ5zlnDILpv9fWhgOiw9XhaC0BOsC+8DQxZCB\nw6kodbUWk03IFGiqAPNNKMFZZHb9B4sC8+G2c/TYnzMJGuPcf/tZaUqi73CThgqk\nCSiAsSWV3D+OaJpCeTsPa4lzpV5tEZjaZbejXUhgvapkVmRsLGvlDSzuu0srKyXu\n17VYwkjI8YSTfMHxrFJQoAzeRd0KmKkwofi/4HISwGMBq6KV0Ri5Falyk4lmC3LV\nPLR8VEzB4NTihzRWxeimfGcqzodwjc7d4sLSFXVnFQgAxt1Aet64bLtiH8UqdfNx\nvC7tkNW3CoPWm1qhCe2kYzeEw7nrpATrHZb4BeGCCGuJN+a10P5vbQo6xTgaTjbX\nlwGcuWAN3JPLCnYBzIgaXawr2uaLUj8ngZFwo5+z2VlzSKbP68L/Te9sJA0kR5uu\nIGBFvtt1f36adWzN9drP+ik6vMq6i2v8W0NIk4Ox3YKvkzxFyNSxG0e97UCjZzkV\nxdehIja5kegD0LpCwxUByisOBm0ZAvUyju1o1PYsTkdIq1+HMuKNdcEvqxgYXRVV\nTRyJWRE3c/s6SapkyFnUgQ8rpFJB9szksLcVihSO2TlycQltK/Kd/cMx01as7ghJ\nVrQFeWVsbG+IewQTEQgAIwUCWQ4HHQIbAwcLCQgHAwIBBhUIAgkKCwQWAgMBAh4B\nAheAAAoJEGgDEFdHybWaw+8A/0qmk8I3NV0HDKqmcYyOZLfcQvUbcbd1LUNWBM7A\n2lUyAP9PWi8vXliL2D5oXAD4HR3lyfSbd4+sI9u5gmOXG1CNZQ==\n=WdLf\n-----END PGP PUBLIC KEY BLOCK-----"


(* Charlie from gpg test cases: DSA with el-gamal encryption key *)
let test_pkp_cstruct = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQGiBDbjkGcRBAC/DCQungO2iJ7j9+9qd2crjBU8K+AmQhs27JBkJqtAbC/xFqkH\nBsA1Pi8Zb6TLa/OCm2PbXFiM5x00wiEnVKNzuGOzU8uHB6kwWtLj8+V7VOWOkSDE\ntnlTF6u0y9JOvs7GwDvqOM5C3QH7La+znNeAu1527Hj6l0XGSAzyvp+NkwCgnktU\n11VFpKSIdoplZBayN9OzT8sD/Awc/890fiSMWYNGo4+n6IHxhjBBM9lL+DAe1RtC\nEtwUSWNrGsIxFnDRkMxvMpaT4GusG+DPhaTddrDBSyFiCLxKDBYgMbSO6wQ9g6zW\nEEh1ZMTMVU/akr81DOEColXn/f3Q4sRjxI3hu2z8tjVewAPNTuWETQ6iHHoVqdpk\nK4aABACfbMrnfK6TujxSs91MfKBWfYxyw9hjM6+VV8cJJdDXiheMKzWcrVecwgYY\nzukmNinO//BRmQcs1wdfi5UdfHLNFDigw96SdyZpHx+79ghD3NqDmzYakoRIoDKc\nZAIrAjgfl5if6vIiA4c1LjhSdcVTBsSyic/mkk01EgztWKY0abQtQ2hhcmxpZSBU\nZXN0IChkZW1vIGtleSkgPGNoYXJsaWVAZXhhbXBsZS5uZXQ+iF0EExECABUFAjbj\nkGcDCwoDAxUDAgMWAgECF4AAEgkQQT9K8xr9q2wHZUdQRwABAT5EAJ9fcDAXA+7n\n6av9/VJr9a/Sb1PnuACfVMEihQSsyol6FBm7vc3S73d+pIq5AQ0ENuOQghAEAKFj\nw1K+7qwrSngPQBUGxHPyJVdiptGVFNkAdLgsJfDH+LwWZ90hedo0s6jKLjhiu5IK\neVl2Hhhaq4LHaaDLAbnz0DNwWFqGaoSU1spvubgX/8QYhkrTNOBbXe1DAb2FNc6F\nh6pyGc45oMPA8QrUav7aj/kA2qGquKfRMUUFYuB3AAMHA/9HTT2zrVf8WRRQCHzD\nhO5rqqd03/YaypezI9iN0XkTeASsryMNwMueI4eqSzBXXtskbzVzMJETklxUUstZ\nAmD1yl6hOk/5hwX6b3CG2zBo4n8s+vHzzyL86aW5IPzVU/7rMGGFNRulrN8sR23d\ndzOlbsI101vKIRyBP7oKv5bYZohOBBgRAgAGBQI245CCABIJEEE/SvMa/atsB2VH\nUEcAAQG1rQCcDbUhj2I23rC0k3kcChgOX32YhQ4An0zwuiPl8hmr4xya2h04Ev20\ngjdD\n=Oem3\n-----END PGP PUBLIC KEY BLOCK-----\n"


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
  | Error _ -> failwith "self_check ascii armor"
  | Ok (tag, pkt_body, _) ->
    (Openpgp.parse_packet tag pkt_body >>=
    begin function
    | (Public_key_packet {algorithm_specific_data = Public_key_packet.DSA_pubkey_asf pub; _}) ->
      let()=Printf.printf "\nPkt len:%d - got a %d-bit DSA key: %s\n"
          Cstruct.(len pkt_body) Z.(numbits pub.p) Public_key_packet.(v4_key_id pkt_body) in
      R.ok ()
    | _ -> failwith "Invalid_packet"
    end); ()
  end

let test_verify_signature _ =
  begin match
      ( Openpgp.decode_ascii_armor test_pkp_cstruct
      |> R.reword_error (fun _ -> -1, `Invalid_packet)
          >>= fun (ascii_packet_type, unasciied) ->
        Openpgp.parse_packets unasciied
  >>= fun pkt_lst ->
  let pk_t, pk_cs =
    begin match List.nth pkt_lst 0 with
      | Public_key_packet x , x_cs_tl -> x , x_cs_tl
      | _ -> failwith "x" end
  in
  let sig_t , sig_cs =
    begin match List.nth pkt_lst 2 with
      | Signature_packet res, pkt ->
        res, pkt
      | _ -> failwith "verify what?" end
  in
  let first_pkts = [Cstruct.of_bigarray ~len:(sig_cs.off) sig_cs.buffer ] in
  let packet_tags =
    let (p,cs) = List.split pkt_lst in
    let p = List.map Openpgp.packet_tag_of_packet p in
    List.combine p cs
  in
  let()=Printf.printf "going to verify everything before %d (%d bytes)\n" sig_cs.off (List.hd first_pkts |> Cs.len)in
  Openpgp.Signature.verify packet_tags pk_t
  |> R.reword_error (fun a -> 31337,a)
 ) with
  | Error (_,`Invalid_signature) ->
      Printf.printf "invalid signature"
  | Error (_,`Unimplemented_feature _) -> Printf.printf "unimp"
  | Error (_,`Nonstandard_DSA_parameters) -> Printf.printf "nonstd dsa params"
  | Error (off,`Invalid_packet) ->
    Printf.printf "invalid packet at offset %d" off
  | Error (off,`Incomplete_packet) -> Printf.printf "incomplete packet: %d" off
  | Error (_,`Unimplemented_algorithm c) -> Printf.printf "no such algo: %C" c
  | Error (_,(`Cstruct_invalid_argument _
             | `Cstruct_out_of_memory)) -> Printf.printf "cstruct fuck"
  | Error (_,`Unimplemented_version _) -> Printf.printf "version bullshit"
  | Error (_, `Extraneous_packets_after_signature) -> Printf.printf "extraneous data after signature\n"
  | Ok _ -> Printf.printf "------ good signature\n"
  end; ()

let test_keys _ =
  let files =
    let dh = Unix.opendir "test/keys/" in
    let rec loop acc =
      begin match Unix.readdir dh with
        | f when Unix.((stat f).st_kind) <> Unix.S_REG ->
          loop acc
        | ".." | "." |"" -> loop acc
        | f  ->
          loop (f::acc)
        | exception End_of_file -> Unix.closedir dh; acc
      end
    in
    loop []
  in
  files ;
  ()

let suite = [
  "unpack_ascii_armor" >:: test_unpack_ascii_armor;
  "self_check" >:: test_self_check;
  "verify_signature" >:: test_verify_signature;
  "keys" >:: test_keys;
  ]
