/*
RCRU64 ransomware
*/


rule RCRU64
{
    meta:
        author = "rivitna"
        family = "ransomware.rcru64.windows"
        description = "RCRU64 ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $a0 = "\x00p2h6\x00" ascii
        $a2 = "\x00n7t0\x00" ascii
        $a3 = "\x00u4g8\x00" ascii
        $a4 = "\x00wenf=\x00" ascii
        $a5 = "\x00udij=\x00" ascii
        $a6 = "\x00d7j3\x00" ascii
        $a7 = "\x00y9a0\x00" ascii
        $a8 = "\x00m5ha\x00" ascii
        $a9 = "\x00Fs1z3\x00" ascii
        $a10 = "\x00nqpso5938fh71jfu\x00" ascii
        $a11 = "\x00U12H6AN==\x00" ascii
        $a12 = "\x00&4r*3d\x00" ascii
        $a13 = "\x00P7A1s\x00" ascii
        $a14 = "C:\\Users\\Unknown\\source\\repos\\ConsoleApplication5_A\\Release\\ConsoleApplication5_A.pdb" ascii
        $a15 = "C:\\Users\\Unknown\\source\\repos\\Decryptor_5\\Release\\Decryptor_5.pdb" ascii
        $a16 = { C7 45 ?? 73 78 75 6F C7 45 ?? 6A 67 64 67 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (7 of ($a*))
        )
}
