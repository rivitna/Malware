/*
Enmity ransomware
*/


rule Enmity
{
    meta:
        author = "rivitna"
        family = "ransomware.enmity.windows"
        description = "Enmity ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h0 = "\\Enmity\\Release\\Enmity.pdb" ascii
        $h1 = "\n\nChoose:\x00" ascii
        $h2 = "CARE=\x00" ascii
        $h3 = "\nDataSize:\x00\x00\n\nID :\x00" ascii
        $h4 = "]ID-[\x00-Mail[\x00" wide
        $h5 = { 68 99 99 01 00 6A 01 5? E8 [4] 83 C4 20 [4-12]
                68 99 99 01 00 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (4 of ($h*))
        )
}
