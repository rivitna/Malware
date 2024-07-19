/*
Babuk ransomware
*/


rule Babuk_ESXi
{
    meta:
        author = "rivitna"
        family = "ransomware.babuk.esxi"
        description = "Babuk ESXi"
        severity = 10
        score = 100

    strings:
        $h0 = "/dev/urandom\x00" ascii
        $h1 = "EiB\x00PiB\x00TiB\x00GiB\x00MiB\x00KiB\x00B\x00" ascii
        $h2 = "crypting: %s\n\x00" ascii

        $c0 = { 67 E6 09 6A [2-8] 85 AE 67 BB [2-8] 72 F3 6E 3C [2-8]
                3A F5 4F A5 [2-8] 7F 52 0E 51 [2-8] 8C 68 05 9B }
        $c1 = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9
                5B C2 56 39 F1 11 F1 59 A4 82 3F 92 D5 5E 1C AB }
        $c2 = { 79 37 9E 89 [4-16] C1 C? ( 15 | 0B ) [16-40] 79 37 9E 89 }

    condition:
        (uint32(0) == 0x464C457F) and (filesize < 120000) and
        (
            (all of ($c*)) and (1 of ($h*))
        )
}
