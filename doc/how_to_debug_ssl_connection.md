# How to debug ssl connection

**Use JVM parameter** to get detailed log for SSL handshake

-Djavax.net.debug=ssl,handshake

## One-way SSL connection
```puml
Client -> Server: Client Hello
return: Server Hello

Server -> Client: EncryptedExtension
Server -> Client: Server certificate message
Server -> Client: CertificateVerify
Server -> Client: Finished handshake
Client -> Server: Finished handshake
Server -> Client: NewSessionTicket stateless post-handshake
```


Client Hello - Client -> Server
```
{
"ClientHello": {
  "client version"      : "TLSv1.2",
  "random"              : "1C F5 E0 85 B8 BE 49 3A 20 C2 C8 91 9E E4 E5 5D 40 84 7D 00 FF CB 54 33 C4 66 88 E6 97 4C 33 5C",
  "session id"          : "56 1D 4B 17 31 42 BE 15 D0 01 2F 42 DD AD 2F 82 58 41 9A 9A 8B BF C3 57 0F E3 AF D2 48 51 6B BA",
  "cipher suites"       : "[TLS_AES_256_GCM_SHA384(0x1302), TLS_AES_128_GCM_SHA256(0x1301), TLS_CHACHA20_POLY1305_SHA256(0x1303), TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C), TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B), TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA9), TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030), TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA8), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F), TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F), TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCAA), TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3), TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E), TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2), TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024), TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028), TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023), TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027), TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B), TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A), TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067), TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040), TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E), TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032), TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D), TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031), TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026), TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A), TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025), TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029), TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A), TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014), TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009), TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013), TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039), TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038), TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033), TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032), TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005), TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F), TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004), TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E), TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D), TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C), TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D), TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C), TLS_RSA_WITH_AES_256_CBC_SHA(0x0035), TLS_RSA_WITH_AES_128_CBC_SHA(0x002F), TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF)]",
  "compression methods" : "00",
  "extensions"          : [
    "status_request (5)": {
      "certificate status type": ocsp
      "OCSP status request": {
        "responder_id": <empty>
        "request extensions": {
          <empty>
        }
      }
    },
    "supported_groups (10)": {
      "versions": [x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]
    },
    "ec_point_formats (11)": {
      "formats": [uncompressed]
    },
    "signature_algorithms (13)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, dsa_sha256, ecdsa_sha224, rsa_sha224, dsa_sha224, ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1]
    },
    "signature_algorithms_cert (50)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, dsa_sha256, ecdsa_sha224, rsa_sha224, dsa_sha224, ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1]
    },
    "status_request_v2 (17)": {
      "cert status request": {
        "certificate status type": ocsp_multi
        "OCSP status request": {
          "responder_id": <empty>
          "request extensions": {
            <empty>
          }
        }
      }
    },
    "extended_master_secret (23)": {
      <empty>
    },
    "session_ticket (35)": {
      <empty>
    },
    "supported_versions (43)": {
      "versions": [TLSv1.3, TLSv1.2, TLSv1.1, TLSv1]
    },
    "psk_key_exchange_modes (45)": {
      "ke_modes": [psk_dhe_ke]
    },
    "key_share (51)": {
      "client_shares": [  
        {
          "named group": x25519
          "key_exchange": {
            0000: 53 4B BE 2A AD 5A 55 B2   98 50 D1 80 6F B7 7A A3  SK.*.ZU..P..o.z.
            0010: 77 3E 08 71 80 E5 4F 57   44 4A 31 53 09 D4 0A 04  w>.q..OWDJ1S....
          }
        },
      ]
    }
  ]
}}
```

Server Hello - Server -> Client

```
{
"ServerHello": {
  "server version"      : "TLSv1.2",
  "random"              : "84 7D D6 C4 E3 DA 2A 90 54 53 B5 7C 12 7B D4 73 76 6F F9 F3 FF 14 F6 37 1F CF DB 8D 5E 5A 65 72",
  "session id"          : "56 1D 4B 17 31 42 BE 15 D0 01 2F 42 DD AD 2F 82 58 41 9A 9A 8B BF C3 57 0F E3 AF D2 48 51 6B BA",
  "cipher suite"        : "TLS_AES_256_GCM_SHA384(0x1302)",
  "compression methods" : "00",
  "extensions"          : [
    "supported_versions (43)": {
      "selected version": [TLSv1.3]
    },
    "key_share (51)": {
      "server_share": {
        "named group": x25519
        "key_exchange": {
          0000: FF FD F0 2A CD BF 60 3B   CC DF BA F0 46 62 75 03  ...*..`;....Fbu.
          0010: DC 61 0F E4 90 EA 0B CB   C4 E8 BA 61 04 51 EF 20  .a.........a.Q. 
        }
      },
    }
  ]
}}
```

Encrypted extensions Server -> Client

```
{
"EncryptedExtensions": [
  "supported_groups (10)": {
    "versions": [x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]
  }
]}
```

Certificate message Server -> Client
``` 
{
"Certificate": {
  "certificate_request_context": "",
  "certificate_list": [  
  {
    "certificate" : {
      "version"            : "v3",
      "serial number"      : "00 C0 A1 65 2C 6C BD D8 13",
      "signature algorithm": "SHA256withRSA",
      "issuer"             : "CN=My Application, O=My Organisation, L=My City, C=DE",
      "not before"         : "2022-07-04 19:26:23.000 MSK",
      "not  after"         : "2023-07-04 19:26:23.000 MSK",
      "subject"            : "CN=My Application, O=My Organisation, L=My City, C=DE",
      "subject public key" : "RSA"}
    "extensions": {
      <no extension>
    }
  },
]
}}
```

Certificate Verify - Server -> Client
```
{
"CertificateVerify": {
  "signature algorithm": rsa_pss_rsae_sha256
  "signature": {
    0000: 64 BB BF B6 C9 BC 7B 6B   E2 1F B8 01 C1 A5 3E F9  d......k......>.
    0010: 7B 78 1C 89 EA CF EA 28   6D 0A 18 30 59 CB 2A 55  .x.....(m..0Y.*U
    0020: FC AB 39 F7 9C 30 41 01   F6 33 CD A5 0C 5E 69 6F  ..9..0A..3...^io
    0030: AE 1A 19 1D C7 07 DB 04   A6 98 E3 20 C3 5B 0A E9  ........... .[..
    0040: F2 73 2C 02 80 B0 B8 2A   CE 1D D5 DA 0F 5E 83 DD  .s,....*.....^..
    0050: 2E B6 FC DB 38 E1 15 7C   F4 ED 63 27 10 DD 04 49  ....8.....c'...I
    0060: 3C 23 99 C9 12 E6 C0 89   79 78 6E 80 64 ED B4 4D  <#......yxn.d..M
    0070: 05 D3 5A 55 04 86 92 52   93 90 55 2A A4 F3 CF 36  ..ZU...R..U*...6
    0080: 59 EF 0B 70 8D 16 4E AC   1E 77 FD CB 7A 8D 59 5B  Y..p..N..w..z.Y[
    0090: C0 7F A1 06 1F 83 EF 48   02 EB 29 C8 61 D2 3C C0  .......H..).a.<.
    00A0: 45 C3 71 83 4A 10 F6 D8   F2 30 3E FD 59 B9 9E 5D  E.q.J....0>.Y..]
    00B0: EC 2A 04 EB E1 A9 7C 68   AB 26 A2 F0 E6 96 B5 46  .*.....h.&.....F
    00C0: AE 17 16 B7 95 D0 CB 97   18 CA DA 81 15 06 30 DE  ..............0.
    00D0: 1F CC 81 C5 68 3C 89 42   1B F0 67 32 F4 7C 9C 39  ....h<.B..g2...9
    00E0: 40 8C BB 80 32 25 9B B2   C9 32 C4 F2 55 37 4A 7C  @...2%...2..U7J.
    00F0: 05 EA 88 60 34 6F 9F 65   77 82 AA 3E 1C F3 14 2E  ...`4o.ew..>....
  }}
}
```

Finished - Server -> Client
```

{
"Finished": {
  "verify data": {
    0000: D0 83 12 EA 01 98 1E 6E   E6 E1 0B D5 3B C3 91 91  .......n....;...
    0010: D1 13 9D E8 ED DA 8F 12   F7 4B D9 34 7E 51 2D 88  .........K.4.Q-.
    0020: 6C E7 46 6B 57 54 2D B4   82 1E 94 A3 09 90 68 EF  l.FkWT-.......h.
  }'}}
```

Finished Client -> Server
``` 
{
"Finished": {
  "verify data": {
    0000: D8 50 9B 07 B7 71 38 B2   34 2C AA 4C B8 DF 37 3F  .P...q8.4,.L..7?
    0010: 84 D4 EA 5D CE 15 D4 0C   E7 09 4F 63 41 75 C4 CA  ...]......OcAu..
    0020: 5F A4 DB 40 89 FC 7A 13   79 75 E2 36 C6 91 68 60  _..@..z.yu.6..h`
  }'}
}
```

New Session Ticket post-handshake - Server -> Client
```
{
"NewSessionTicket": {
"ticket_lifetime"      : "86,400",
"ticket_age_add"       : "<omitted>",
"ticket_nonce"         : "01",
"ticket"               : {
0000: 84 68 0F DC B7 C6 B7 62   BF 79 06 5C C9 8E 90 CA  .h.....b.y.\....
0010: 10 78 DA 82 A0 E8 21 CC   06 4F B9 9E 9D 00 34 82  .x....!..O....4.
0020: B7 0D 84 30 62 66 91 7D   30 1C EC 49 09 23 97 F1  ...0bf..0..I.#..
0030: A1 DA 15 74 7C 25 CF 47   43 9B 2A 97 54 72 C2 84  ...t.%.GC.*.Tr..
0040: 3F AF 8E 37 70 1A B4 A7   AA 9A C3 CE 42 20 22 1C  ?..7p.......B ".
0050: 05 A2 2C DA 8B 5F F2 91   29 6D B2 D7 23 F5 93 E7  ..,.._..)m..#...
0060: 2E C8 57 AE 92 B2 17 0A   72 F2 A2 2A CE CB F1 82  ..W.....r..*....
0070: 48 8E C3 A8 BC C3 84 26   5E F3 B8 87 F3 1B 78 BE  H......&^.....x.
0080: 78 61 2B 94 1F 80 C8 D4   1D AA 8E 8D AA 84 DA B2  xa+.............
0090: A4 A4 ED 33 9B 0E 5D 49   38 4C 1D 23 FE 16 96 97  ...3..]I8L.#....
00A0: 46 4F 8E E2 90 C2 DE 82   2D 1E 69 3B B4 EA 46 23  FO......-.i;..F#
00B0: CD 14 21 C4 91 6A F4 4E   A9 97 AF 48 15 9D 30 65  ..!..j.N...H..0e
00C0: 87 00 BC DF 53 AB 0B F8   FE 69 FA 43 73 AA 9B 2E  ....S....i.Cs...
00D0: A6 57 D3 55 7C 36 59 43   F1 46 EA EF 79 CC 90 BF  .W.U.6YC.F..y...
00E0: B0 59 BE F5 EE BF 6C 3A   29 3A 77 53 1D 80 C6 0D  .Y....l:):wS....
00F0: 17 CB F4 8D 36 14 96 88   9C D8 EE B2 C2 45 D4 C5  ....6........E..
0100: 50 67 7F F4 6F 8E C4 72   A7 C0 A5 FE 3B 58 99 72  Pg..o..r....;X.r
0110: B2 62 F0 58 3D BA 34 E3   03 51 51 20 1D 9B DC 7B  .b.X=.4..QQ ....
0120: 54 3E 1B E5 BC 11 49 CC   EA C2 18 03 49 BB 03 01  T>....I.....I...
0130: 1F D3 80 17 CF 29 B5 11   B9 B5 33 B9 9A 94 C7 52  .....)....3....R
0140: EC 0D 3C 4B 7B 1B A5 CD   28 D9 9A 39 AE 57 B0 D0  ..<K....(..9.W..
0150: 4D 8B 78 F2 37 20 C7 21   E6 F0 9C FA A6 66 CD C6  M.x.7 .!.....f..
0160: DE 43 D9 EB 3D 73 65 8A   BF D1 EB A0 70 C3 C5 D0  .C..=se.....p...
0170: D7 4D 07 70 F6 BD 01 70   07 8B 90 B2 0A 2A 0E B6  .M.p...p.....*..
0180: DD 71 A2 1E 02 56 09 BF   2C 30 31 5C 96 66 90 32  .q...V..,01\.f.2
0190: 22 77 44 3B 8C D5 A7 08   DC D8 6B 33 01 0F AA F9  "wD;......k3....
01A0: 4D 5C F3 CD 86 B2 B6 01   78 A6 A9 1B EE E4 19 AB  M\......x.......
01B0: 1E 27 E6 79 6C 1A 59 B1   C6 2D 1B 06 2A A7 0C DB  .'.yl.Y..-..*...
01C0: 0C 4E 53 39 5B DD 79 AA   9F 4C FA 31 48 B8 8B 7F  .NS9[.y..L.1H...
01D0: 13 8E 0D 53 E8 8F 3F 9B   F9 E7 07 A6 B5 D2 A1 F9  ...S..?.........
01E0: 3B 27 32 FF 51 CF 8C 2C   7E 4F 72 92 C9 3A 12 01  ;'2.Q..,.Or..:..
01F0: C7 B3 03 19 E6 93 9E DD   C7 32 A8 4C 82 69 20 ED  .........2.L.i .
0200: 64 C6 66 C5 E1 F3 9A 19   D1 65 30 65 8A E7 E4 F1  d.f......e0e....
0210: 55 C3 78 B8 7C 26 FC E2   24 AF 2C 44 9C 35 BC E9  U.x..&..$.,D.5..
0220: 0B 44 01 DC A5 CD D9 94   2F A1 D1 4D 7B E2 14 48  .D....../..M...H
0230: 19 33 D4 11 75 E9 F1 62   9B C4 E7 B1 E9 56 EB 44  .3..u..b.....V.D
0240: A2 5C 59 C0 CD EA 57 51   B0 21 DC 25 64 41 37 19  .\Y...WQ.!.%dA7.
0250: 12 29 65 57 9A 5A 7E 78   40 3C 00 F3 9C 6E 9D 4B  .)eW.Z.x@<...n.K
0260: E1 0B 22 21 D9 B0 DE E1   00 BD 00 E8 13 72 D3 40  .."!.........r.@
0270: 8D D5 09 3E 5F A1 82 6A   E9 A4 EC 87 1B 95 15 0C  ...>_..j........
0280: E4 0D F5 46 2E 15 BA CB   9A 00 10 F4 9C 35 59 6C  ...F.........5Yl
0290: 70 2A 84 84 99 0F 4B 56   B8 53 98 3C BE C6 F6 E6  p*....KV.S.<....
02A0: DD 87 8E 89 39 69 D9 2E   E0 84 D8 F1 A4 F0 AE 24  ....9i.........$
02B0: BC C7 59 F9 CD 58 F7 5E   D8 ED 60 92 72 88 AA 4A  ..Y..X.^..`.r..J
02C0: C4 4D EB B9 CD 9F A0 B7   38 78 FD C3 BC 89 43 72  .M......8x....Cr
02D0: 1F 94 2B 30 C5 34 64 C9   F3 D4 44 97 AE 14 FD 58  ..+0.4d...D....X
02E0: 6C FF 81 B5 58 7E 9B 36   44 CD 23 30 B3 AE 3B 22  l...X..6D.#0..;"
02F0: 37 E4 8C E3 FA 4D 2B 29   F6 61 F0 48 EC 8F 52 F8  7....M+).a.H..R.
0300: 72 13 92 1D 91 34 05 43   A3 66 04 7F 20 58 14 2C  r....4.C.f.. X.,
0310: F2 97 7A E2 ED 45 C1 52   75 9D 05 2E 03 C8 C7 51  ..z..E.Ru......Q
0320: 9E 02 16 EA F8 D5 5C 67   1D 5C DD B2 CB 04 F0 FC  ......\g.\......
0330: 6E DF B1 8A D8 A2 B1 1C   F9 61 2B 09 0F 37 42 C4  n........a+..7B.
0340: 20 B1 B7 9C CC E8 D0 07   2A A3 AB 62 EE 65 D6 EE   .......*..b.e..
0350: F7 B0 A4 90 E2 A7 C5 EF   00 C7 0A 93 50 9F A4 9D  ............P...
0360: E7 D5 64 3E 10 E6 71 F0   74 29 F3 24 8B 4F 85 53  ..d>..q.t).$.O.S
0370: F1 AF 52 73 72 59 E9 F8   0E C4 43 03 A5 9D 42 9D  ..RsrY....C...B.
0380: 7D D0 5D 24 A3 45 3C 5C   41 EE 78 5B 29 E9 C3 6F  ..]$.E<\A.x[)..o
0390: E9 05 07 2F C9 CE 0E E4   64 C2 35 B3 D2 A5 35 0E  .../....d.5...5.
03A0: 10 A5 EE 79 7D 8E CD 6B   F8 D2 77 DB 40 B8 0D A0  ...y...k..w.@...
03B0: 4D 67 A6 55 D7 A6 DC EC   2B F0 17 25 BC 43 83 03  Mg.U....+..%.C..
03C0: 81 EF D2 32 62 41 8F 83   BC D3 74 48 50 00 FF 03  ...2bA....tHP...
03D0: E9 8A 28 84 1A 8D 18 09   C1 52 F4 E7 49 5B B1 16  ..(......R..I[..
03E0: AD AA 83 98 2B D7 FE AC   6A DA 90 8B A7 F6 A3 37  ....+...j......7
03F0: 82 C9 40 0C AB 2A 5D 9F   DE 6E DC B9 71 DD 8F EC  ..@..*]..n..q...
0400: 7B 39 49 80 81 55 6F 35   C4 35 9D 20 F3 2A B1 85  .9I..Uo5.5. .*..
0410: 11 50 A4 A7 31 E2 6D BB   E7 E7 A8 02 49 96 28 EF  .P..1.m.....I.(.
0420: 3C 0A E0 BE
}  "extensions"           : [
<no extension>
]
}}
```


## Two-way SSL connection

```puml
Client -> Server: Client Hello
return: Server Hello
Server -> Client: EncryptedExtension
Server -> Client: Certificate
Server -> Client: CertificateVerify
Server -> Client: Finished
Client -> Server: Certificate
Client -> Server: CertificateVerify
Client -> Server: Finished
Server -> Client: NewSessionTicket stateless post-handshake
```

Client Hello: Client -> Server
```
"ClientHello": {
  "client version"      : "TLSv1.2",
  "random"              : "42 18 AE 94 88 DC 18 8B AD D3 74 4B CE 32 BF 8B 27 FE E6 68 BB 96 2F D3 20 0C 28 68 49 94 BB A2",
  "session id"          : "36 F4 9F D7 EE 72 F5 91 9A 06 73 72 36 8F CA C6 37 E6 3F BA 17 38 36 59 82 93 16 5C 5B 42 EC 03",
  "cipher suites"       : "[TLS_AES_256_GCM_SHA384(0x1302), TLS_AES_128_GCM_SHA256(0x1301), TLS_CHACHA20_POLY1305_SHA256(0x1303), TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C), TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B), TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA9), TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030), TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA8), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F), TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F), TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCAA), TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3), TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E), TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2), TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024), TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028), TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023), TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027), TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B), TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A), TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067), TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040), TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E), TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032), TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D), TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031), TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026), TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A), TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025), TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029), TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A), TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014), TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009), TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013), TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039), TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038), TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033), TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032), TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005), TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F), TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004), TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E), TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D), TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C), TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D), TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C), TLS_RSA_WITH_AES_256_CBC_SHA(0x0035), TLS_RSA_WITH_AES_128_CBC_SHA(0x002F), TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF)]",
  "compression methods" : "00",
  "extensions"          : [
    "status_request (5)": {
      "certificate status type": ocsp
      "OCSP status request": {
        "responder_id": <empty>
        "request extensions": {
          <empty>
        }
      }
    },
    "supported_groups (10)": {
      "versions": [x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]
    },
    "ec_point_formats (11)": {
      "formats": [uncompressed]
    },
    "signature_algorithms (13)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, dsa_sha256, ecdsa_sha224, rsa_sha224, dsa_sha224, ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1]
    },
    "signature_algorithms_cert (50)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, dsa_sha256, ecdsa_sha224, rsa_sha224, dsa_sha224, ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1]
    },
    "status_request_v2 (17)": {
      "cert status request": {
        "certificate status type": ocsp_multi
        "OCSP status request": {
          "responder_id": <empty>
          "request extensions": {
            <empty>
          }
        }
      }
    },
    "extended_master_secret (23)": {
      <empty>
    },
    "session_ticket (35)": {
      <empty>
    },
    "supported_versions (43)": {
      "versions": [TLSv1.3, TLSv1.2, TLSv1.1, TLSv1]
    },
    "psk_key_exchange_modes (45)": {
      "ke_modes": [psk_dhe_ke]
    },
    "key_share (51)": {
      "client_shares": [  
        {
          "named group": x25519
          "key_exchange": {
            0000: 04 34 82 30 60 FD 79 14   DF 2E 3F 41 27 71 82 73  .4.0`.y...?A'q.s
            0010: 9F A4 2B C3 BE E1 E8 18   9F 3D 3B 16 8E 2C AB 42  ..+......=;..,.B
          }
        },
      ]
    }
  ]
}
```

Server Hello: Server -> Client
```
"ServerHello": {
  "server version"      : "TLSv1.2",
  "random"              : "E9 D0 5F 9E 12 27 7B FB F5 25 BA 57 2D 41 35 0D 79 22 B1 3A CB 0D B8 46 50 1F 0C 00 B6 48 4C ED",
  "session id"          : "36 F4 9F D7 EE 72 F5 91 9A 06 73 72 36 8F CA C6 37 E6 3F BA 17 38 36 59 82 93 16 5C 5B 42 EC 03",
  "cipher suite"        : "TLS_AES_256_GCM_SHA384(0x1302)",
  "compression methods" : "00",
  "extensions"          : [
    "supported_versions (43)": {
      "selected version": [TLSv1.3]
    },
    "key_share (51)": {
      "server_share": {
        "named group": x25519
        "key_exchange": {
          0000: E5 3C 7A BB 2C 70 47 EA   1C DB 3E 08 AE D4 22 95  .<z.,pG...>...".
          0010: 65 11 B7 7E 92 16 EB D5   8F 69 81 A8 F0 12 7F 3E  e........i.....>
        }
      },
    }
  ]
}
```

Encrypted Extensions: Server -> Client
```
"EncryptedExtensions": [
  "supported_groups (10)": {
    "versions": [x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]
  }
]
```

Certificate Request: Server -> Client
```
"CertificateRequest": {
  "certificate_request_context": "",
  "extensions": [
    "signature_algorithms (13)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, ecdsa_sha1, rsa_pkcs1_sha1]
    },
    "signature_algorithms_cert (50)": {
      "signature schemes": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, ecdsa_sha1, rsa_pkcs1_sha1]
    },
    "certificate_authorities (47)": {
      "certificate authorities": [
        CN=My Other Application, O=My Organisation, L=My City, C=DE]
    }
  ]
}
```

Certificate: Server -> Client
```
"Certificate": {
  "certificate_request_context": "",
  "certificate_list": [  
  {
    "certificate" : {
      "version"            : "v3",
      "serial number"      : "00 C6 B1 6A 5E 84 75 86 92",
      "signature algorithm": "SHA256withRSA",
      "issuer"             : "CN=My Application, O=My Organisation, L=My City, C=DE",
      "not before"         : "2022-07-04 19:55:51.000 MSK",
      "not  after"         : "2023-07-04 19:55:51.000 MSK",
      "subject"            : "CN=My Application, O=My Organisation, L=My City, C=DE",
      "subject public key" : "RSA"}
    "extensions": {
      <no extension>
    }
  },
]
}
```

Certificate Verify: Server -> Client
```
"CertificateVerify": {
  "signature algorithm": rsa_pss_rsae_sha256
  "signature": {
    0000: 3D ED 21 38 08 65 B7 9B   4F E7 7F 70 57 B5 62 65  =.!8.e..O..pW.be
    0010: A9 59 BB AB 3A 83 BD 7C   65 86 E4 47 1D EC 1D BD  .Y..:...e..G....
    0020: 2E DD 61 42 5C 97 92 06   B5 6B 1E 6F 87 BB 3B 32  ..aB\....k.o..;2
    0030: E9 3F 33 8C 48 68 B1 B9   2D 0A 27 73 D8 B8 93 54  .?3.Hh..-.'s...T
    0040: 6E C2 CB 9C 65 7C 4C CA   3A 9A E9 E8 79 2C DF 56  n...e.L.:...y,.V
    0050: EB 48 47 34 05 D8 DD 18   83 5D 8D 98 23 2A 0F 34  .HG4.....]..#*.4
    0060: 7C 08 14 89 47 AF 70 8B   30 7B 79 8F 0D D8 7F 01  ....G.p.0.y.....
    0070: 1F 50 77 89 52 AA F0 CD   E6 D8 76 89 80 A6 E7 9B  .Pw.R.....v.....
    0080: 71 6C 94 C8 22 E6 0F C0   04 EF 12 E7 7D 8C 6F 3E  ql..".........o>
    0090: 73 9D AC A1 1A FB EC 75   36 E6 83 85 AC 2F 99 9D  s......u6..../..
    00A0: 0C FA C6 B9 02 46 30 40   E1 27 22 B8 75 D9 8B 1C  .....F0@.'".u...
    00B0: BD D9 AF ED 5A 3E 81 9B   48 C8 3D CF A0 0A 7B 5D  ....Z>..H.=....]
    00C0: EF FE 6E 11 F1 68 5D CC   E8 A4 0E A6 69 9C D1 EE  ..n..h].....i...
    00D0: 79 7E E7 EB A8 A5 5A AD   50 3B F4 30 5B 78 C6 25  y.....Z.P;.0[x.%
    00E0: CF 3A 11 C1 E2 69 B6 35   F1 BF 84 C3 11 FC A1 42  .:...i.5.......B
    00F0: 9A EC DC 25 46 81 A7 E3   99 7E FD 03 67 FB 97 BF  ...%F.......g...
  }
}

```

Finished: Server -> Client
```
"Finished": {
  "verify data": {
    0000: 33 08 45 AE CA 2F 28 68   60 28 D9 32 28 EA 3A B0  3.E../(h`(.2(.:.
    0010: 24 95 63 1C EE C7 F1 FB   60 3C AF 7E 00 23 3A 8B  $.c.....`<...#:.
    0020: 02 84 A3 58 63 86 45 A4   41 16 E0 A9 09 3D 47 49  ...Xc.E.A....=GI
  }'}
```

Certificate: Client -> Server
```
"Certificate": {
  "certificate_request_context": "",
  "certificate_list": [  
  {
    "certificate" : {
      "version"            : "v3",
      "serial number"      : "0C B5 10 39 48 EC 0B 21",
      "signature algorithm": "SHA256withRSA",
      "issuer"             : "CN=My Other Application, O=My Organisation, L=My City, C=DE",
      "not before"         : "2022-07-04 19:55:52.000 MSK",
      "not  after"         : "2023-07-04 19:55:52.000 MSK",
      "subject"            : "CN=My Other Application, O=My Organisation, L=My City, C=DE",
      "subject public key" : "RSA"}
    "extensions": {
      <no extension>
    }
  },
]
}
```

Certificate Verify: Client -> Server

```
"CertificateVerify": {
"signature algorithm": rsa_pss_rsae_sha256
"signature": {
0000: 4E 7F 1E 70 B3 38 20 7A   F2 07 D4 C7 82 6E 4A 98  N..p.8 z.....nJ.
0010: 0D 11 0D 63 3D 3A 58 E1   4D 64 D9 24 B9 0A 3D 64  ...c=:X.Md.$..=d
0020: 07 0D 1E 3C 92 1F 91 B1   8A 84 2C 7D 14 85 37 A3  ...<......,...7.
0030: 71 BE 63 E4 46 32 76 75   46 C7 05 4B 23 CC CA 63  q.c.F2vuF..K#..c
0040: 97 7F 18 20 3D E2 87 A3   F9 07 B6 15 B6 38 9D F2  ... =........8..
0050: 95 21 1B 1F 4D 72 A8 03   A4 17 E1 BA BD F9 E9 E0  .!..Mr..........
0060: D6 D2 33 B3 D4 FE 48 80   C2 E5 9F F8 D7 BE A2 54  ..3...H........T
0070: 14 A5 75 F0 4A 9A A7 10   B9 E4 F5 16 AD 2B 2C 48  ..u.J........+,H
0080: A5 4C 50 3C EA 51 23 67   0F 2D AC F1 D8 FD A3 28  .LP<.Q#g.-.....(
0090: CF 3F 73 BA F2 C6 FC 16   83 A6 E9 2D AE A5 C3 65  .?s........-...e
00A0: 5E AD 55 44 06 08 2D 2D   E0 D3 A1 FC C3 FB DC 21  ^.UD..--.......!
00B0: 47 5A 31 81 10 49 6B A3   77 C8 9F 01 7B 24 DD 0A  GZ1..Ik.w....$..
00C0: 1D 26 FD 1B D8 30 64 C5   96 9E F1 2D 04 D9 94 9E  .&...0d....-....
00D0: A2 3A 1C AE CB D8 70 EE   68 FA D5 1C 5C F9 84 F8  .:....p.h...\...
00E0: B9 98 4B A2 90 75 FB 95   39 A1 A5 1A 58 93 C2 3C  ..K..u..9...X..<
00F0: 95 52 10 FE F8 7B 57 B0   A7 68 E2 29 AD D8 BC 59  .R....W..h.)...Y
}
}
```

Finished: Client -> Server

```
"Finished": {
  "verify data": {
    0000: D0 19 ED 61 6D 51 8C F7   55 8A 43 A7 4F B0 CF 27  ...amQ..U.C.O..'
    0010: D5 F3 20 83 21 41 77 C7   79 DF 75 49 B1 63 7C D7  .. .!Aw.y.uI.c..
    0020: 24 6D DF ED 29 23 89 FE   42 D7 61 B2 DB 9C D3 4B  $m..)#..B.a....K
  }'}
```

New Session Ticket: Server -> Client
```
"NewSessionTicket": {
  "ticket_lifetime"      : "86,400",
  "ticket_age_add"       : "<omitted>",
  "ticket_nonce"         : "01",
  "ticket"               : {
    0000: 44 0F 10 28 74 7D BA E8   50 5B C0 DC E6 28 A4 D8  D..(t...P[...(..
    0010: 62 BD 21 CA 46 14 20 8F   38 C4 AA 4F 85 C6 E1 1C  b.!.F. .8..O....
    0020: 48 E2 A2 76 8B 6F 2E 5B   24 3B 0B 13 45 17 FC 06  H..v.o.[$;..E...
    0030: 64 C1 A9 62 BA 7E 69 DC   A6 34 FF 7A 79 A4 C5 CA  d..b..i..4.zy...
    0040: B8 1C 3E 64 0A 7B B3 1B   2F EF 1F 61 C2 3A 55 92  ..>d..../..a.:U.
    0050: C6 60 5E 4F 5D 13 67 B7   33 9B 49 FC 75 7E D4 40  .`^O].g.3.I.u..@
    0060: E5 D2 0B A2 44 04 33 1B   10 E8 C7 32 4E 99 7C B2  ....D.3....2N...
    0070: 78 55 C9 B4 1C 3D 9F 08   EC 35 81 26 0B 81 16 71  xU...=...5.&...q
    0080: F0 E7 EE AB 46 E7 9F 14   59 84 17 B4 25 76 29 B1  ....F...Y...%v).
    0090: F2 C6 50 F7 EE BE C0 7E   11 92 0D C0 F4 75 69 6D  ..P..........uim
    00A0: 44 8B DD AA 4C 6F FE 89   89 42 DC BD 83 F9 35 90  D...Lo...B....5.
    00B0: 36 1B 66 1F D6 23 AF F6   C9 D3 E3 D6 71 A5 B1 EB  6.f..#......q...
    00C0: 81 70 CF D7 43 C7 7B AD   08 02 0F D0 8C 55 86 8E  .p..C........U..
    00D0: BE CE 69 16 A8 97 E5 E0   26 E2 19 8C A7 F4 57 49  ..i.....&.....WI
    00E0: 97 A2 46 E8 19 76 E7 87   63 19 2C 40 9A DB 14 63  ..F..v..c.,@...c
    00F0: A8 1C 64 98 9B A0 AD 23   6E 18 70 F5 7D 35 EA 75  ..d....#n.p..5.u
    0100: BB 23 F0 53 62 AD 9A F7   90 92 B1 F1 22 C6 EC CD  .#.Sb......."...
    0110: 83 58 F4 2D 4C 1E 4E E2   A9 34 D6 25 BF 61 75 CE  .X.-L.N..4.%.au.
    0120: 1F 35 E4 C3 BB 39 56 40   CB A9 8B 30 0E A7 F7 50  .5...9V@...0...P
    0130: 46 D8 0E 31 20 99 A1 46   11 2D 0F 46 47 46 D2 E6  F..1 ..F.-.FGF..
    0140: 5F FE A5 6F E8 2A 2C D1   1E A2 3C 5B FF 2F BE 2C  _..o.*,...<[./.,
    0150: D5 8F EB C1 C6 34 78 51   09 BD 82 0F EA 54 AF 25  .....4xQ.....T.%
    0160: 0E 02 88 46 8A E7 8A 3C   AE 63 35 7F 9F 5C CB 14  ...F...<.c5..\..
    0170: B2 3F 68 84 2E 46 4D BE   A9 6A A2 11 D3 B0 C3 9A  .?h..FM..j......
    0180: 20 C2 92 FA DC 8A DC E5   7F 65 0B 5F 45 A4 0E F4   ........e._E...
    0190: CB 8F 1F 90 D5 0B 83 06   11 B7 84 FB A2 E2 6C E3  ..............l.
    01A0: 1D FC 8F BC 3A 1C E3 77   3A 84 64 AF 5E 4F 82 D8  ....:..w:.d.^O..
    01B0: 46 2F 1F 8A 14 5A 24 41   5F 04 31 B1 22 15 E5 4F  F/...Z$A_.1."..O
    01C0: 1B 17 42 CC C7 24 2C A5   73 CA 97 2D 33 6E 8A 1B  ..B..$,.s..-3n..
    01D0: EA 0D CA DA F8 31 20 3B   FB 93 16 97 0A 58 CF 64  .....1 ;.....X.d
    01E0: 6A FE 50 54 E1 C6 73 F3   50 F7 92 48 E4 D7 F4 ED  j.PT..s.P..H....
    01F0: E9 9E 13 E6 DE 97 36 D8   F8 20 4E C2 A5 9C D1 D2  ......6.. N.....
    0200: 91 EE 3B 8F 5C CC 31 A6   F2 1C 77 0F 2B 77 EC 62  ..;.\.1...w.+w.b
    0210: D5 4D 45 F7 1C B3 5E 64   56 72 4E 67 C7 DA 34 C5  .ME...^dVrNg..4.
    0220: 33 1E 1D CB C7 6B 99 A1   10 4A 1E 04 0B 74 A0 9F  3....k...J...t..
    0230: 18 C9 95 A0 C1 1D 64 98   2B C7 E0 12 0C AE 94 CC  ......d.+.......
    0240: D5 F7 CD DA E5 CD 29 AC   19 B0 C7 C0 D3 68 EE E7  ......)......h..
    0250: 7C B4 13 42 A1 91 01 9E   6D 17 84 CD EB 94 D0 8A  ...B....m.......
    0260: 25 D8 DF E7 D3 3B 02 78   AE EE C1 11 90 79 13 62  %....;.x.....y.b
    0270: 64 B6 1F 10 0D 1B D2 5F   25 58 72 5A E1 34 56 69  d......_%XrZ.4Vi
    0280: 64 2A 31 10 75 34 28 EB   41 0D E4 83 20 0F FB 95  d*1.u4(.A... ...
    0290: 9E 69 36 47 7B 8A 92 E8   5A AF 81 CB 47 49 E9 16  .i6G....Z...GI..
    02A0: 04 88 BE CE A7 EA A0 99   1B 26 EC 38 13 7C ED ED  .........&.8....
    02B0: 08 94 A3 5D 8A D4 52 A4   D0 68 0A C3 5C 05 92 B4  ...]..R..h..\...
    02C0: 17 5F 4B C7 E9 0E 4E 0C   A1 33 C3 FE 56 35 32 59  ._K...N..3..V52Y
    02D0: 20 77 ED E3 59 CB 3C 82   30 61 C6 F9 A8 0E A2 0D   w..Y.<.0a......
    02E0: 89 8B 15 31 14 B1 30 6A   A1 FA 28 46 AE C2 D8 D1  ...1..0j..(F....
    02F0: E6 2E 50 6E 7D 10 40 23   34 A5 9A 1A 70 09 DA 19  ..Pn..@#4...p...
    0300: CE 81 87 87 5D 81 52 BC   33 2E 64 D4 57 45 52 82  ....].R.3.d.WER.
    0310: F3 2C 8C E1 E6 61 39 8B   CA 7D E2 F2 D1 4F 58 A5  .,...a9......OX.
    0320: 09 E0 17 14 FB 74 BE 06   12 D5 DC 61 D1 F9 65 BE  .....t.....a..e.
    0330: D9 10 8F 81 C2 9E 91 4C   65 87 11 A8 00 F1 74 32  .......Le.....t2
    0340: 41 25 DC D2 7B 82 3F 7A   4F 3D D7 8A D2 06 41 B7  A%....?zO=....A.
    0350: 95 E7 22 12 5B 9F 3E E1   F4 71 ED DC 12 20 5E EC  ..".[.>..q... ^.
    0360: A4 39 BA 58 5A A2 5F 86   95 15 01 07 79 AE C2 48  .9.XZ._.....y..H
    0370: B6 A6 55 21 3B AF 0A 0B   79 A9 9F 36 AD 8E C9 DE  ..U!;...y..6....
    0380: 8A 70 9C 14 37 AE 06 9F   FD C8 98 BD A1 BE 15 79  .p..7..........y
    0390: 50 CF 7D 3E DF BA F4 A9   F3 78 75 A9 AC 78 3D 60  P..>.....xu..x=`
    03A0: F5 76 2F 84 C3 25 E0 D2   AC C2 25 68 5B E7 FA 18  .v/..%....%h[...
    03B0: AF CB BC 15 97 36 71 AD   1B D3 76 0E 7C 0F 41 0E  .....6q...v...A.
    03C0: 1B 2B B4 8C 01 F1 84 E1   95 1B AC 6C 59 CC 1E 23  .+.........lY..#
    03D0: B9 5B 5F 4A E4 2D E3 81   F8 B5 0A 9A EF 40 9E 45  .[_J.-.......@.E
    03E0: F3 95 3A 0F 73 AE 69 43   14 CA C3 75 46 EC E5 FA  ..:.s.iC...uF...
    03F0: DB 26 00 C3 D8 58 E0 B0   D6 9E 39 97 D8 DC E0 69  .&...X....9....i
    0400: C8 84 9E 1F 7F D7 0A CE   31 CC D7 7F D6 59 D0 6B  ........1....Y.k
    0410: 92 F8 E9 4C C7 8A D9 C3   4E 46 35 37 D3 97 63 57  ...L....NF57..cW
    0420: 74 16 D5 58 95 7D 0D 6C   26 9D 50 7A 97 F6 86 AD  t..X...l&.Pz....
    0430: 76 C3 25 7D B5 66 A5 C4   FF 50 E0 83 88 18 D5 AD  v.%..f...P......
    0440: CA 61 FE D8 2C 92 38 84   58 E5 68 5F C1 FB 1E CC  .a..,.8.X.h_....
    0450: 06 95 66 0B 1A 85 0C 96   01 F9 68 F5 CD C8 5B 16  ..f.......h...[.
    0460: 4E 45 24 29 23 94 14 AA   4F E0 D6 D7 03 28 AB 32  NE$)#...O....(.2
    0470: 7E 70 23 17 2F F3 02 21   35 90 29 C9 35 54 7B CA  .p#./..!5.).5T..
    0480: 4F E6 7C 60 63 43 A6 EE   42 C7 EA FB 8F 5D 43 37  O..`cC..B....]C7
    0490: 22 56 39 89 3E 8B EC A7   3F AF 14 9F 27 EE 25 1C  "V9.>...?...'.%.
    04A0: 79 4A C9 AE F7 A7 44 8F   BD AA CC EB F4 FE F1 98  yJ....D.........
    04B0: BF 48 C0 97 A0 3B 93 80   78 FB 23 12 87 B4 53 DF  .H...;..x.#...S.
    04C0: 1D E6 B3 7F 90 8C DD 07   A0 5C F9 7A 9A D4 33 91  .........\.z..3.
    04D0: 0A AF 9D 7E 34 D0 74 82   D4 B2 80 2C 94 05 08 11  ....4.t....,....
    04E0: 97 10 17 B2 25 B1 13 10   98 B8 F8 45 53 B4 C3 3B  ....%......ES..;
    04F0: 43 0A BB 8C 12 B7 84 14   CC 76 74 BE CC D0 F2 78  C........vt....x
    0500: 51 9D AF 91 20 9F C4 5A   54 27 78 84 1C AA 8D E3  Q... ..ZT'x.....
    0510: DD 84 C1 2D BB B8 92 6E   A4 E0 86 8E 2E 8F 65 E4  ...-...n......e.
    0520: 56 04 E7 17 E2 99 00 B4   B9 E0 ED 88 29 CC FD C8  V...........)...
    0530: 9F CC 1C F4 C7 9F 39 88   90 33 90 35 83 FF 5D 25  ......9..3.5..]%
    0540: 78 0F 30 78 FB B1 A7 BD   28 00 45 ED 47 45 67 64  x.0x....(.E.GEgd
    0550: 96 6B 09 B6 AA 71 A5 C0   09 BC C1 51 2C CB 5F 85  .k...q.....Q,._.
    0560: E0 C7 A6 99 D2 C7 5A D4   9E 32 67 B8 D7 0A A8 0F  ......Z..2g.....
    0570: A3 A6 90 7A 59 10 FE 4F   63 2F 02 0D 4B DB 5A C3  ...zY..Oc/..K.Z.
    0580: C6 0D 52 9E F2 66 33 C0   A3 D6 8A BB A1 5D F3 67  ..R..f3......].g
    0590: EB BD 8B 03 C9 12 B5 15   05 16 2A 9E 47 F6 A9 AA  ..........*.G...
    05A0: 86 FD 1C A5 8A CF B7 0B   9B DD 78 77 02 59 81 CB  ..........xw.Y..
    05B0: 14 40 5D AD E5 5B 49 B3   DC 8A 91 28 24 D9 60 EF  .@]..[I....($.`.
    05C0: 88 F1 7D 66 32 9D 31 3B   53 E2 70 BB DE 60 5E A9  ...f2.1;S.p..`^.
    05D0: 4A 86 D7 80 4D 60 62 A1   58 04 C7 44 83 54 9F 29  J...M`b.X..D.T.)
    05E0: F5 04 9C 96 67 68 39 77   2B 15 7A 17 49 57 E7 FE  ....gh9w+.z.IW..
    05F0: 3A 86 F7 35 A8 B5 29 C6   39 66 D3 2B 41 D5 E0 CF  :..5..).9f.+A...
    0600: 82 DF 0F DE 71 35 AD F3   12 4B D2 77 BC A9 92 86  ....q5...K.w....
    0610: 49 74 8E CA D4 F9 D8 5C   4C 76 91 A8 A1 6C 9A FD  It.....\Lv...l..
    0620: F9 C1 22 44 98 37 E4 B6   A5 C7 6D 82 E7 10 84 CF  .."D.7....m.....
    0630: 0C 53 52 AA F8 12 F9 CB   C2 F1 91 83 36 57 DA 99  .SR.........6W..
    0640: AF 3A 13 9E 00 39 44 9B   46 AC 64 D0 94 C3 78 1A  .:...9D.F.d...x.
    0650: 9E 45 48 13 D0 23 8E 7C   76 0D D6 1F 63 65 1B 13  .EH..#..v...ce..
    0660: E5 D1 36 0B C9 19 28 93   29 49 F4 0B 9A CB A0 38  ..6...(.)I.....8
    0670: C6 FE 81 5D 38 8E 8B 10   80 2B C6 92 E7 94 2A 51  ...]8....+....*Q
    0680: FC DE D3 B5 C6 58 4E 1F   31 BB 85 E5 99 27 FA 1C  .....XN.1....'..
    0690: F7 A9 AE 09 4B 8B 36 46   BE AE 1C 3A 42 04 14 26  ....K.6F...:B..&
    06A0: 87 31 EB D6 F1 07 55 95   CC 00 68 78 E4 B9 23 D8  .1....U...hx..#.
    06B0: ED 2A 31 D7 8D 76 05 03   64 44 96 8F 10 02 42 8B  .*1..v..dD....B.
    06C0: 1F 57 9C 2F E2 99 8D 36   7E E4 15 2F AF EF 91 65  .W./...6.../...e
    06D0: 75 56 1D B8 E5 D6 54 41   54 6C AE 56 E0 4A F4 ED  uV....TATl.V.J..
    06E0: DB C8 58 C6 8B A6 D1 B6   84 F1 18 A1 F0 7A EC 95  ..X..........z..
    06F0: 4A 7C 93 E0 A6 E3 EC D6   3F BC 23 95 59 14 74 D1  J.......?.#.Y.t.
    0700: 04 13 0A 70 80 AF D0 F5   CF 2D 50 F3 9C 7B A9 6B  ...p.....-P....k
    0710: 7E BB 4A BB AF AD B0 11   B2 61 28 62 64 E4 D2 F1  ..J......a(bd...
    0720: 7E 15 AB 6A 5F 6B 8B BB   94 59 20 58 11 D3 13 8F  ...j_k...Y X....
    0730: 08 81 B1 44 AA 7A A3 E8   BD E2 AD DE 0F FD 91 FB  ...D.z..........
    0740: 39 DE C1 42 CA CA 12 8A   8B 49 8A 26 9D AD 01 F7  9..B.....I.&....
    0750: 03 F3 64 28 DA 38 37 B5   4F AA A5 92 
  }  "extensions"           : [
    <no extension>
  ]
}
```