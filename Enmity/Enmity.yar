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
        $h1 = "\\Mammon\\Release\\Mammon.pdb" ascii
        $h2 = "CARE=\x00" ascii
        $h3 = "\x00\nMail:\x00\x00\nData" ascii
        $h4 = { 5D 00 49 00 44 00 2D 00 5B 00 00 00 ( 2D | 2E ) 00
                4D 00 61 00 69 00 6C 00 ( 2D 00 5B | 5B ) 00 00 00 }
        $h5 = "QWERTYUIOPASDFGHJKLMNBVCXZqwertyuiopasdfghjklz1234567890xcvbnm" ascii
        $h6 = "\x00space\x00\x00\x00create_directories\x00\x00current_path()\x00" ascii
        $h7 = { 68 99 99 01 00 6A 01 5? E8 [4] 83 C4 20 [4-12]
                68 99 99 01 00 }
        $h8 = { FF FF E8 03 10 00 0F 86 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (4 of ($h*))
        )
}
