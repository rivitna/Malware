/*
Proton ransomware
*/


rule Proton
{
    meta:
        author = "rivitna"
        family = "ransomware.proton"
        description = "Proton ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "4B991369-7C7C-47AA-A81E-EF6ED1F5E24C" ascii
        $s1 = ".[<EMAIL>]<EXTENSION>\x00" wide
        $s2 = "\x00<BACKUP_EMAIL>\x00" wide
        $h0 = { 81 F? 00 00 20 03 ( 73 | 7D ) ?? B? 10 00 00 00 [2-18]
                81 F? 00 00 40 06 ( 73 | 7D ) ?? B? 20 00 00 00 [2-18]
                81 F? 00 00 40 1F ( 73 | 7D ) ?? B? 40 00 00 00 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            ((1 of ($h*)) and (1 of ($s*))) or
            (3 of them)
        )
}
