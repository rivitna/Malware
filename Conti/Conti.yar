/*
Conti 2 and 3 ransomware
*/


rule Conti
{
    meta:
        author = "rivitna"
        family = "ransomware.conti.windows"
        description = "Conti 2 and 3 ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 85 ?? 0F 84 ?? 0? 00 00 ( 0F B6 00 | 8A 0? ) 3C E9 74 1?
                3C FF 0F 85 ?? 0? 00 00 80 7? 01 25 0F 85 }
        $h1 = { 45 33 C9 C7 44 24 ?? 0C 02 00 00 [0-4] 33 D2 48 89 [8-12]
                45 8D 41 01 FF D0 85 C0 }
        $h2 = { 83 C4 08 8D 4D ?? 68 0C 02 00 00 5? 5? 6A 00 6A 01 6A 00
                FF 75 ?? FF D0 }
        $h3 = { ( 2D 5B 00 00 | DA FC 01 B8 ) ( 41 83 | 83 ) F? 04 7C ??
                [12-24] 69 0? 95 E9 D1 5B ( 48 83 | 83 ) C2 04
                ( 45 69 | 69 ) ?? 95 E9 D1 5B }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (2 of ($h*))
        )
}
