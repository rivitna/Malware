/*
Akira ransomware
*/


rule Akira
{
    meta:
        author = "rivitna"
        family = "ransomware.akira.windows"
        description = "Akira ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "\x00--encryption_path\x00" ascii wide
        $s1 = "\x00--share_file\x00" ascii wide
        $s2 = "\x00--encryption_percent\x00" ascii wide
        $s3 = "\x00-fork\x00" ascii
        $s4 = "\x00-localonly\x00" ascii wide
        $s5 = "\x00Failed to read share files\x00" ascii wide
        $s6 = ":\\akira\\asio\\include\\" ascii
        $s7 = "\x00write_encrypt_info error: \x00" ascii
        $s8 = "\x00encrypt_part error: \x00" ascii
        $s9 = "\x00Detected number of cpus = \x00" ascii
        $s10 = "\x00No path to encrypt\x00" ascii
        $s11 = "Paste this link - https://akira" ascii
        $s12 = "\x00Trend Micro\x00" wide
        $s13 = "Failed to make full encrypt" ascii wide
        $s14 = "Failed to make spot encrypt" ascii wide
        $s15 = "Failed to make part encrypt" ascii wide
        $s16 = "Failed to write header" ascii wide
        $s17 = "file rename failed. System error:" ascii wide
        $s18 = "Number of thread to folder parsers = \x00" ascii
        $s19 = "Number of threads to encrypt = \x00" ascii
        $s20 = "Number of thread to root folder parsers = \x00" ascii
        $s21 = "Failed to read share files!\x00" ascii

        $h0 = { 41 BA 05 00 00 00 41 80 FB 32 44 0F 42 D0 33 D2 48 8B C?
                49 F7 F2 4C 8B C8
                ( B? 02 00 00 00 [0-4] 41 B? 04 00 00 00 |
                  41 B? 04 00 00 00 [0-4] B? 02 00 00 00 )
                41 80 FB 32 44 0F 42 C? 41 8B C8 4? 0F AF C? 48 2B F9 33 D2
                48 8B C7 49 F7 F2 }
        $h1 = { C7 45 ?? 03 00 00 00 80 7D ?? 31 76 07 C7 45 ?? 05 00 00 00
                0F B6 45 ?? 48 0F AF 45 ?? 48 C1 E8 02
                48 B? C3 F5 28 5C 8F C2 F5 28 48 F7 E? 48 89 ?? 48 C1 E8 02 }

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            (7 of ($s*)) or
            (1 of ($h*))
        )
}
