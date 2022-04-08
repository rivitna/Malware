/*
Dharma ransomware
*/


rule Dharma
{
    meta:
        author = "rivitna"
        family = "ransomware.dharma"
        description = "Dharma ransomware Windows"
        severity = 10
        score = 100

    strings:
        $h0 = { C7 4? 08 FD 03 AA 78 [0-8] C7 4? 0C 03 00 00 00 [0-8]
                C7 4? 10 00 00 04 00 [0-8] C7 4? 18 38 00 0C 00 }
        $h1 = { C7 4? 04 02 00 00 00 [0-8] C7 4? 08 0C FE 7A 41 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (1 of ($h*))
        )
}
