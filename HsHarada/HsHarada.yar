/*
HsHarada / Rapture ransomware
*/


rule HsHarada
{
    meta:
        author = "rivitna"
        family = "ransomware.hsharada"
        description = "HsHarada ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $a0 = { 09 45 00 4C 00 53 00 4D 00 }
        $a1 = { FE 09 00 00 8D 2? 00 00 01 80 }
        $a2 = "CheckRemoteDebuggerPresent\x00" ascii
        $a3 = "RSACryptoServiceProvider\x00" ascii
        $a4 = "RijndaelManaged\x00" ascii

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (filesize < 100000) and
        (
            (4 of ($a*))
        )
}
