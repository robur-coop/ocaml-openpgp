open QCheck
open QCheck.Test
open Rresult
open Openpgp

let test_pkp_cstruct = Cs.of_string
"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQMuBFkOBx0RCADSbRim2QNp+1nZKePQ7Oc8TmYXSdP/789Uitw7KVG4vpWsQ49k\nP/GqCbWcCGVoiMg3UVVCBR6KxEvc33TMfsicoLN8ucVXF6RXwFcyBIh0aFRBhNvI\nTj1jvGmOP9QGCYUUXUZ92AXw9LPtK13mC0DjUlPcQ2rpzw5+MZItU1GcJOI1bSyF\nc11gHGm16zs999KCr3ufK0cHvMTbnHPYNPzcj2QVaKiRjp0BpGAtzTQZ29igW00r\nQZqhz38bBvsSU1HdLl8SqiyxGv/+jvnS2HYsWjJBD8oFn4+4Qol3YBdWZBZbJhQ4\nPMxdUQXdGUIjXKLUguwvnqiA7UVsSHverq9zAQDcpJDs4KZIDSKUJR97yNMjf9so\n6HuU4y6yitSrDIKJPQf6Al3ndlyVtfmXsZz/1zDQ1qCsYauQjE6fO2XqOrkOtzz+\n8KP3sizP/CzADJO8YUSJKT+I29ZtQ5zlnDILpv9fWhgOiw9XhaC0BOsC+8DQxZCB\nw6kodbUWk03IFGiqAPNNKMFZZHb9B4sC8+G2c/TYnzMJGuPcf/tZaUqi73CThgqk\nCSiAsSWV3D+OaJpCeTsPa4lzpV5tEZjaZbejXUhgvapkVmRsLGvlDSzuu0srKyXu\n17VYwkjI8YSTfMHxrFJQoAzeRd0KmKkwofi/4HISwGMBq6KV0Ri5Falyk4lmC3LV\nPLR8VEzB4NTihzRWxeimfGcqzodwjc7d4sLSFXVnFQgAxt1Aet64bLtiH8UqdfNx\nvC7tkNW3CoPWm1qhCe2kYzeEw7nrpATrHZb4BeGCCGuJN+a10P5vbQo6xTgaTjbX\nlwGcuWAN3JPLCnYBzIgaXawr2uaLUj8ngZFwo5+z2VlzSKbP68L/Te9sJA0kR5uu\nIGBFvtt1f36adWzN9drP+ik6vMq6i2v8W0NIk4Ox3YKvkzxFyNSxG0e97UCjZzkV\nxdehIja5kegD0LpCwxUByisOBm0ZAvUyju1o1PYsTkdIq1+HMuKNdcEvqxgYXRVV\nTRyJWRE3c/s6SapkyFnUgQ8rpFJB9szksLcVihSO2TlycQltK/Kd/cMx01as7ghJ\nVrQFeWVsbG+IewQTEQgAIwUCWQ4HHQIbAwcLCQgHAwIBBhUIAgkKCwQWAgMBAh4B\nAheAAAoJEGgDEFdHybWaw+8A/0qmk8I3NV0HDKqmcYyOZLfcQvUbcbd1LUNWBM7A\n2lUyAP9PWi8vXliL2D5oXAD4HR3lyfSbd4+sI9u5gmOXG1CNZQ==\n=WdLf\n-----END PGP PUBLIC KEY BLOCK-----"


(* Charlie from gpg test cases: DSA with el-gamal encryption key *)
(*let test_pkp_cstruct = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQGiBDbjkGcRBAC/DCQungO2iJ7j9+9qd2crjBU8K+AmQhs27JBkJqtAbC/xFqkH\nBsA1Pi8Zb6TLa/OCm2PbXFiM5x00wiEnVKNzuGOzU8uHB6kwWtLj8+V7VOWOkSDE\ntnlTF6u0y9JOvs7GwDvqOM5C3QH7La+znNeAu1527Hj6l0XGSAzyvp+NkwCgnktU\n11VFpKSIdoplZBayN9OzT8sD/Awc/890fiSMWYNGo4+n6IHxhjBBM9lL+DAe1RtC\nEtwUSWNrGsIxFnDRkMxvMpaT4GusG+DPhaTddrDBSyFiCLxKDBYgMbSO6wQ9g6zW\nEEh1ZMTMVU/akr81DOEColXn/f3Q4sRjxI3hu2z8tjVewAPNTuWETQ6iHHoVqdpk\nK4aABACfbMrnfK6TujxSs91MfKBWfYxyw9hjM6+VV8cJJdDXiheMKzWcrVecwgYY\nzukmNinO//BRmQcs1wdfi5UdfHLNFDigw96SdyZpHx+79ghD3NqDmzYakoRIoDKc\nZAIrAjgfl5if6vIiA4c1LjhSdcVTBsSyic/mkk01EgztWKY0abQtQ2hhcmxpZSBU\nZXN0IChkZW1vIGtleSkgPGNoYXJsaWVAZXhhbXBsZS5uZXQ+iF0EExECABUFAjbj\nkGcDCwoDAxUDAgMWAgECF4AAEgkQQT9K8xr9q2wHZUdQRwABAT5EAJ9fcDAXA+7n\n6av9/VJr9a/Sb1PnuACfVMEihQSsyol6FBm7vc3S73d+pIq5AQ0ENuOQghAEAKFj\nw1K+7qwrSngPQBUGxHPyJVdiptGVFNkAdLgsJfDH+LwWZ90hedo0s6jKLjhiu5IK\neVl2Hhhaq4LHaaDLAbnz0DNwWFqGaoSU1spvubgX/8QYhkrTNOBbXe1DAb2FNc6F\nh6pyGc45oMPA8QrUav7aj/kA2qGquKfRMUUFYuB3AAMHA/9HTT2zrVf8WRRQCHzD\nhO5rqqd03/YaypezI9iN0XkTeASsryMNwMueI4eqSzBXXtskbzVzMJETklxUUstZ\nAmD1yl6hOk/5hwX6b3CG2zBo4n8s+vHzzyL86aW5IPzVU/7rMGGFNRulrN8sR23d\ndzOlbsI101vKIRyBP7oKv5bYZohOBBgRAgAGBQI245CCABIJEEE/SvMa/atsB2VH\nUEcAAQG1rQCcDbUhj2I23rC0k3kcChgOX32YhQ4An0zwuiPl8hmr4xya2h04Ev20\ngjdD\n=Oem3\n-----END PGP PUBLIC KEY BLOCK-----\n"*)


let test_pkp_cstruct = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFmZ1HwBCACaZ4imh+tENAoOsxrCOMpZBDztHxKEtECr4J1MY3qBg4Bv4wAO\ngAgyqGxI5axWwqwnMFCM5fxhF2eUNaobtGzhoNLLJNZOfkcUNjx14muVfNmJcSWj\nTsXEDdVD+jUld7djTs61O2c7At2heu+6285oOOGMMhoRbz9ObI3BFE8jmJ3+j5JL\nc3MI6PAzSE6AD6LZ/zlesjeu9HGu8A9qhDvImTDPjwFJXg6DvcaAT+hGWkGIPQ1d\nsU4pbjxkWkiqtKROHWOd78FnPhxVo2q+54DKr05F/KwZJupMBrkXu0n6XywBASwZ\nejSQ1HE08ebCOXRZcwzays308pFv4LhWvt5HABEBAAG0B2FjYWJtYW6JAVQEEwEI\nAD4WIQQgTw05kJawJ5NQJy0MPBKlUuTiswUCWZnUfAIbAwUJA8JnAAULCQgHAgYV\nCAkKCwIEFgIDAQIeAQIXgAAKCRAMPBKlUuTisz9pB/95VybDKux1YeS7++F9HBeK\nm22eaWpFxLkGraobE/2/inYMjpEBr+hPjq1HQZ3qd3cVAK9ffX8lGPdOprREp1HZ\n/fWGCkRK6i2X4KlKq5hDiWHcdWZZCoRwWNIVTG042XER50dZ2FteEahthyG+liYN\nWrY1Ni8BJP2osaq9dAq4LQVtRxxFiXtNya863dZ4Phso2cNUqGn7blWgVcbNDp2i\n/cQaI1bko74yjp6mi4SOKBEQ+/4q/7fIGfrDcDYE6f0DnGLCrgNl9/608kUCdFFS\nG3v5ebe3dZ1Uj0ps0ZckzvQEiDAgKiA6Y5LLj64mpRN7c35DkfiPX/ClPQFc8nDr\nuQENBFmZ1HwBCADqoTBVjsapmjSteH3XdHxnfXkMYfGQ6G5cw8Mky1JrIxMsHGLe\nVekirsYIYKsu7W42wTMb1v/YburI49nWnHCsGKQL1XgJIsCHqbAcTNZboFj6Vj8w\ny9fpMXQz+Jck/+WbBLGyN3tdJppSMvjiXS1BBorGBj+25sZURWmk0p0ak8GmSzO0\n/bHbSExiH6xwie1xhX3k3dC8ZyHXWZZhIHfyB/1jxKk0nmUM7ieAMxC1OirXbO7k\n9GT7/h9K7iE1+LzBepCQrZJP763f55pDRBD5/PpLM7Y1hA1WV/P5ovAiJAUnII+p\nipv7YDxSV12vr3cRK2ZjCpG4JOVbbTL73PtLABEBAAGJATwEGAEIACYWIQQgTw05\nkJawJ5NQJy0MPBKlUuTiswUCWZnUfAIbDAUJA8JnAAAKCRAMPBKlUuTis2lVB/9L\ntpWfsNaZKIBdpvsJWMT8SFV0l1ajWcShWoS8p2ie3tMtLMyfCWZFRuMnCuwq8Grp\n7NLBubkP7KAId9f+VKAWzCuXfyOE74MEATv5JQZbsB2H+twkri6J9GzhSdyF0qzP\nZnL9JpI5E75aonFrx/dJOC4exES/AVnjlIEzn8dQ4FlH9JU6XvERGF5KAcmJIF1w\nfFu9Vy7cA1QTdSgDQfB4Kq4PqOM78rflZQ8DeFbpx+2/YfLhdzAaC8GaG4HCZ2dc\nVvXN+BNpiK7Un0IRa7lnxcd/DEzTSuNtJVQpBgIpkn8XoQ/XpheOJFUFwuCF3Grb\nZ+2+zifnxC7DaHGkflcD\n=aDp3\n-----END PGP PUBLIC KEY BLOCK-----\n"

(* gpg test key "three" (RSA) *)
(*let test_pkp_cstruct = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmIwEP/JTvQEEAKhSVnbs5Ndf5tAHPyv5mm9JM8691FKK9W5MYeL3MSRzk2Rd2vWO\nrdVlKcJTl3gjZGPfLUWFIOgONMBYJCs/+I3Tmog7R1tmzqq7yZif8B/+c3Zg6bYb\nudyRIF1Cj//o9nX672E2WMctptdQwOvECvYj0gZpLIJRTEBNiCWrcBABAAkBAbQm\nVGVzdCB0aHJlZSAobm8gcHApIDx0aHJlZUBleGFtcGxlLmNvbT6ItQQTAQIAHwUC\nP/JTvQIbAwcLCQgHAwIBAxUCAwMWAgECHgECF4AACgkQ0SC2Juyr9R1qQwP/bCDX\n1WGk1u0zkKJWJ/VXnuH3jk6ZevkuHZICwjlqAxv1de5P3Jeya/4kPmEQTotEv3xc\nDAZ+9pBL3TrZolAKhxkBZ08l4QSy76kyf8hB0eoZ2Svs7LrGPBJr6CHX0kyDiapH\ngAhBKQq9GhNKpIAZuL6DK2dOaQDtoRSW2iB1h4k=\n=AznS\n-----END PGP PUBLIC KEY BLOCK-----\n"*)

(* dsadetached *)
let test_dsadetached_pkp_cstruct = Cstruct.of_string "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFmh98EBCADZ9gU9XpIG5F/foxEKHwuQvW1kxXEWoL0PmNHYFvk5mJ4Z8qud\nPdG372GKgGsesXq2OrRZDufU46G/1OKrkyzHP6A/LmJtoLSaurH4IjS8o6uEQY3p\n4Ieiit0gZmJDGV0Zw2KaT0fLbkKjsqhYSTijdBLFuIRKpWb+QxYrFyabTWuZQQvo\nuI468I1NUXrM9IedG0QjObjIs364QTqflwpKdwTvR22acLyK+6ITNWhDFf+W2Qsp\nTVnsMYGkuybCNvj2in8QEGvS+vrrmY/WS0PEeOxZi2wus6PiCTrXOE53CvXBInYY\nz4rQF/Omf7FFnCiOJRbFvbgluEYPPwVJI8FXABEBAAG0CWRzYWRldGFjaIkBVAQT\nAQgAPhYhBMaNrC3BbdNI4yigWiSH+4kvvXl2BQJZoffBAhsDBQkDwmcABQsJCAcC\nBhUICQoLAgQWAgMBAh4BAheAAAoJECSH+4kvvXl226kH/jNQZ5ONutJoG0ZlJ1C0\ntR15tXbVwBWVX+XnoZENtDE+7luTS9dw7ZHFcUmmerXI+eF5R4aoLAGfqiO4Awx7\nB73sA2sFUQaLew+Za4QYdtB2mhmC+iva8+X1uQcYD0U//6jr16PXX1zcsMNvcJaL\nrtK3E6WWTSKmbT2QhDYWZjihmeVpvUioF/FY14BQqU0INDTdcA+AROPT1pVWmZHg\n+PfziEx24xHFvfxwFLaQExopGs8aoxYkyL4Q0Pv2unWazMqOA/GcWV9QQT/3KgVS\nCfvWf4Sqjd2nR/sg0XuxzRT3y2peDuyNCwByLGcXkdt32OF7UWGs9j69wirfO1MW\nghK5AQ0EWaH3wQEIALRjYPqDVXJ/kfGHx2TwtUjk84GY4tS2uzn+4cSpe5qlijlk\nYYNdnb7dOxfMUOzEJ3q6ZJKqbmqA1HUET6x0+R5V0ygm2Kq6VzFnLUHSMERic4DY\npXhQRI65fON50tSmQlOLefjB52emwDPL8qZosCdCbqrTNLMnA9ildihjstQ9BLdV\nFqsTnIbG2ZrbzuOvJBSekl+42zNLJ2z/zCqkUgolxGlC5r9m11z9iFHniig1I9DQ\nqJR0YGZiM9dhBBmrI2uBlxcPN8XgAuQU1Qn+qRkQo8kQwx6Eqgzx9kedUYP4waDO\nTQZtBUMo36FilybIuN+0iYivwcxYLNcm+hIzfs0AEQEAAYkBPAQYAQgAJhYhBMaN\nrC3BbdNI4yigWiSH+4kvvXl2BQJZoffBAhsMBQkDwmcAAAoJECSH+4kvvXl2ZqcH\n/iGBKQf1v1x+kYY2wFuW50a6xs+xWhYXTXeJfeZqtokJp1wLOW1RZApYNT4+O5Dd\nICJXtj6ZYkE7V+wdIMGm/Sz9iuYNQxXEZBLGU/UTgyYdljfw10XkoE80D1Zzp+jS\nIY1qNAydYn3W8FmWeJfjth+BbhBvbp4G9Tf/h0vZhJAtXny9wSU88dI4qyCf232C\nlDH/UySWJoQsiDufEzehyrViaUbPZOf0K0ODTDoA3+D7Ee0V4fSX4s0jjg8xsEVO\nODKhNUyhTNXbL3keK3KNMypf6fNs4pqiWhbdt8KY3wK+k9UYt2iMxNbRBlZqXpZd\nyUQL25J7qlHjLrLovo7hrnQ=\n=bYCm\n-----END PGP PUBLIC KEY BLOCK-----\n"

let test_message_cstruct = Cstruct.of_string "-----BEGIN PGP MESSAGE-----\n\nowEBWQGm/pANAwAIAQw8EqVS5OKzAawSYgdtc2cudHh0WZnVNWFjYWIKiQEzBAAB\nCAAdFiEEIE8NOZCWsCeTUCctDDwSpVLk4rMFAlmZ1TUACgkQDDwSpVLk4rOu1Af+\nIVSX6xvGnq+Z8kISi3GpenOiRIcODoJJWaxoGOhihrHVfbTHlKqy5sWEPuzAliuS\nWxd+IkRL2kkjuAC9AXpvLU4I+20V5fguJeuBupuMg31C3UG77o5OSFHVXQ6Il+kg\nqP4a8iWmMc1SNWM3IorJzem6SpTd2LRcAIIgEeEO9daCmULjkyd4tq+pkunK9NBT\nXkBdO9j1XauCPhXMlNiPZ15TqbyxxzwwFCv4lEGnYxMS5f8k4PVb+MxFvlKyCP3n\noyKUZudhl7HzHoHhPEKGfOvnLgeonsdl64JbfsULx5IafAFLEocIXOf7ESPr+zvc\nifuRylT4/JL/6VjyCKbkcQ==\n=SWh9\n-----END PGP MESSAGE-----\n"
let test_dsadetached_cstruct = Cstruct.of_string "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEExo2sLcFt00jjKKBaJIf7iS+9eXYFAlmh+GQACgkQJIf7iS+9\neXZM+Af/RQAAfPxy6Fa+Md3ik8gH1gTvW9q3qfPL7mukxNJmudMApfW7pIgnVRTO\n4ajqnIzPngymBQRfGGETbpiIAOBnbpVqFxrYNfaH4ky2NWJJVzslIV5q6bDzvth0\nXUeO2kI3jeK8rKOk/Gp/mBgzJpUXxHQI3MEABJ5StXGQvfHA5TEIIAOMxNO27uNq\nP9MnQ05eeTskZpcuQpAIHoIfDBqZi4ypTxsbxoqYKhy5LdrvhIeXmqw5s9XxLVxv\ndqkwappuXvGvrVWsh6QS7r1DcCTH7zUHrP9qzMBwg5taG0Xn5GQ1MiZ/HqOlJd7A\nhVYC6hE3dUruDiSIYqMjPgQtcN1S/g==\n=qOcl\n-----END PGP SIGNATURE-----"

let test_msg_cstruct = Cstruct.of_string "acab\n"

let asciiz =
  (* generate strings without nullbytes *)
  let ig = QCheck.Gen.int_range 1 0xff in
  let cg = QCheck.Gen.map (char_of_int) ig in
  QCheck.Gen.string ~gen:cg |> QCheck.make

let test_unpack_ascii_armor _ =
  check_exn @@ QCheck.Test.make ~count:1
    ~name:"unpack ascii armor"
    (unit) @@ (fun () ->
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
   >>= fun (_, unasciied) ->
   Openpgp.next_packet unasciied
   >>= begin function
     | (Some (packet_tag, pkt_body, next_packet)) ->
        Ok (packet_tag, pkt_body, next_packet)
     | _ -> failwith "unable to parse unasciied"
   end
  )|>
  begin function
    | Error (`Incomplete_packet) -> failwith "self_check need more bytes"
    | Error (`Invalid_packet) -> failwith "self_check: invalid packet"
  | Error _ -> failwith "self_check ascii armor"
  | Ok (tag, pkt_body, _) ->
    let _ = (Openpgp.parse_packet_body tag pkt_body >>=
    begin function
      | (Public_key_packet _
        ) ->
      let()=Printf.printf "\nPkt len:%d - got a key: %s\n"
          Cstruct.(len pkt_body) Public_key_packet.(v4_key_id pkt_body) ;
                Logs.debug (fun m -> m "Got a good public key packet")
      in
      R.ok ()
    | _ -> failwith "Invalid_packet"
    end) in ()
  end

let test_verify_signature _ =
  begin match
      ( Openpgp.decode_ascii_armor test_pkp_cstruct
      |> R.reword_error (fun _ -> -1, `Invalid_packet)
          >>= fun (_, unasciied) ->
        Openpgp.parse_packets unasciied
  >>= fun pkt_lst ->
  let _ =
    begin match List.nth pkt_lst 0 with
      | Public_key_packet x , x_cs_tl -> x , x_cs_tl
      | _ -> failwith "x" end
  in
  let _ , sig_cs =
    begin match List.nth pkt_lst 2 with
      | Signature_type res, pkt ->
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
  Openpgp.Signature.root_pk_of_packets packet_tags
  |> R.reword_error (fun a -> 31337,a)
 ) with
  | Error (_,`Invalid_signature) ->
      Printf.printf "invalid signature"
  | Error (_,`Unimplemented_feature _) -> Printf.printf "unimp"
  | Error (_,`Nonstandard_DSA_parameters) -> Printf.printf "nonstd dsa params"
  | Error (off,`Invalid_packet) ->
    Logs.debug (fun m -> m "invalid packet at offset %d" off); failwith "Invalid packet"
  | Error (off,`Incomplete_packet) -> Printf.printf "incomplete packet: %d" off
  | Error (_,`Unimplemented_algorithm c) -> Printf.printf "no such algo: %C" c
  | Error (_,(`Cstruct_invalid_argument _
             | `Cstruct_out_of_memory)) -> Printf.printf "cstruct fuck"
  | Error (_,`Unimplemented_version _) -> Printf.printf "version bullshit"
  | Error (_, `Extraneous_packets_after_signature) -> Printf.printf "extraneous data after signature\n"
  | Ok _ -> Printf.printf "------ good signature\n"
  end; ()

let fix_parse_packets pkt_lst =
  let (p,cs) = List.split pkt_lst in
  List.combine (List.map Openpgp.packet_tag_of_packet p) cs

let test_detached _ =
  let _ =
    Openpgp.decode_ascii_armor test_dsadetached_pkp_cstruct |> R.reword_error (fun a -> -1,a)
  >>| snd
  >>= Openpgp.parse_packets >>| fix_parse_packets
  >>= (fun x -> Openpgp.Signature.root_pk_of_packets x |> R.reword_error (fun a -> -1,a))
  >>= fun (root_pk , _) ->
  let()= Logs.debug (fun m -> m "Got a root pk for detached") in
  Openpgp.decode_ascii_armor test_dsadetached_cstruct |> R.reword_error (fun a -> -1,a)
  >>= fun (_, cs) ->
  (* TODO match on Ascii_message *)
  let()= Logs.debug (fun m -> m "Decoded ascii armored detached signature") in
  Ok cs >>= Openpgp.parse_packets >>| fix_parse_packets >>= fun what ->
  let()= Logs.debug (fun m -> m "Got a detached sig") in
  Ok what
  >>= fun ((a,b)::_) ->
  Openpgp.parse_packet_body a b |> R.reword_error (fun a -> -1,a)
  >>= fun (Signature_type detached_sign) ->
  let data = ref (Some (Cstruct.of_string "acab\n")) in
  let cb () =
    match !data with (Some _) as x -> data:=None; Ok x | non -> Ok non
  in
  begin match Openpgp.Signature.verify_detached_cb root_pk detached_sign cb with
    | Ok _ -> Ok ()
    | Error _ -> failwith "detached sig failed"
  end
in ()

let test_keys _ =
  let dir = "test/keys/" in
  let files =
    let dh = Unix.opendir dir in
    let rec loop acc =
      begin match Unix.readdir dh with
        | f when Unix.((stat (dir ^ f)).st_kind) <> Unix.S_REG ->
          loop acc
        | ".." | "." |"" -> loop acc
        | f  ->
          loop (f::acc)
        | exception End_of_file -> Unix.closedir dh; acc
      end
    in
    loop []
  in
  let _ = files in ()

let suite = OUnit2.[
  "unpack_ascii_armor" >:: test_unpack_ascii_armor;
  "self_check" >:: test_self_check;
  "verify_signature" >:: test_verify_signature;
  "keys" >:: test_keys;
  "detached" >:: test_detached;
  ]
