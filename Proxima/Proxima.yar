/*
Proxima ransomware
*/


rule Proxima
{
    meta:
        author = "rivitna"
        family = "ransomware.proxima.windows"
        description = "Proxima ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "hardcore blowjob\x00" ascii
        $s1 = "\x00BCryptOpenAlgorithmProvider\x00" ascii
        $s2 = "\x00-nonetdrive\x00" wide
        $s3 = " /TN \"Windows Update BETA\" /" wide
        $s4 = "\x00/c \"%s\" /SHUTDOWN\x00" wide
        $s5 = "\x00/c \"%s\" /RESTART\x00" wide
        $s6 = "\x00Global\\FSWiper\x00" wide
        $s7 = "\x00\\\\?\\%hc:\\0F3LWP.tmp\x00" wide
        $s8 = "\x00A:\\\x00B:\\\x00C:\\\x00D:\\\x00E:\\\x00F:\\\x00G:\\" wide
        $s9 = "\x00Mounted %s as %s\x00" wide
        $s10 = "\x00Unable To Access File: %s - SHARING_VIOLATION\x00" wide
        $s11 = "\x00Unable To Access File: %s - ACCESS_DENIED\x00" wide
        $s12 = "\x00Unable To Rename File: %s - %lu\x00" wide
        $s13 = "\x00Start Enumeration: %s\x00" wide
        $s14 = "\x00Finished Exploring Large Files on: %s\x00" wide
        $s15 = "\x00Finished Exploring Small Files on: %s\x00" wide
        $s16 = "\x00READ - %lu - %s\x00" wide
        $s17 = "\x00WRITE - %lu - %s\x00" wide
        $s18 = "\x00WRITE_FOOTER - %lu - %s\x00" wide
        $s19 = "\x00UNDEFINED ERROR - %lu - %s\x00" wide
        $s20 = "\x00DEQUEUE ERROR\x00" wide
        $s21 = "\x00%lu I/O Workers Created\x00" wide
        $s22 = "\x00Waiting For I/O Workers\x00" wide
        $s23 = "\x00Encryption Completed\x00" wide

        $h0 = { 83 C? FF [0-10] B? 20 00 00 00 [0-16] 0F B6 0? 8D ?? 01 8B ??
                C1 E? 08 C1 E? 18 33 ?? [0-4] 33 ?4 ?? [4] 83 E? 01 75 E? }
        $h1 = { 85 D2 7C 1? 7F 08 81 F9 00 00 ?? 00 72 0? B9 00 00 ?? 00
                89 ( 8D ?? F? FF FF | 4D ?? )
                ( 8D 81 ?? 0? 00 00 50 6A 08 FF 35 | 81 C1 ?? 0? 00 00 E8 ) }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (7 of ($s*)) or
            ((1 of ($h*)) and (2 of ($s*)))
        )
}
