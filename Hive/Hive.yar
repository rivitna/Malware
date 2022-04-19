/*
Hive ransomware
*/


rule Hive_v3
{
    meta:
        author = "rivitna"
        family = "ransomware.hive"
        description = "Hive v3 ransomware Windows/Linux/FreeBSD payload"
        severity = 10
        score = 100

    strings:
        $h0 = { B? 03 52 DA 8D [6-12] 69 ?? 00 70 0E 00 [14-20]
                8D ?? 00 90 01 00 }
        $h1 = { B? 37 48 60 80 [4-12] 69 ?? 00 F4 0F 00 [2-10]
                8D ?? 00 0C 00 00 }
        $h2 = { B? 3E 0A D7 A3 [2-6] C1 E? ( 0F | 2F 4?)
                69 ?? 00 90 01 00 }

        $x0 = { C6 84 24 ?? 00 00 00 FF [0-14] 89 ?? 24 ?? 00 00 00 [0-6]
                89 ?? 24 ?? 0? 00 00 [0-20] C6 84 24 ?? 0? 00 00 34 }
        $x1 = { C6 44 24 ?? FF [0-14] 89 ?? 24 ?? [0-6] 89 ?? 24 ?? [0-12]
                C6 ( 84 24 ?? 00 00 00 | 44 24 ?? ) 34 }

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            (2 of ($h*)) or (1 of ($x*))
        )
}


rule Hive_ESXI_v3
{
    meta:
        author = "rivitna"
        family = "ransomware.hive.esxi"
        description = "Hive v3 ransomware ESXI payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 48 69 ?? B5 B4 1B 01 48 C1 E? 20 69 ?? 00 70 0E 00 29 ?? }
        $h1 = { 48 69 ?? 25 30 40 00 48 C1 E? 20 69 ?? 00 F4 0F 00 29 ?? }

        $a0 = "\\.(vm|vs)\\w+$\x00" ascii
        $a1 = "vim-cmd vmsvc/getallvms | grep -o -E '^[0-9]+' | xargs -r -n 1 vim-cmd vmsvc/power.off" ascii

        $b0 = "\x00%s.key.%s\x00" ascii
        $b1 = "\x00! export %s" ascii
        $b2 = "\x00+ export %s" ascii
        $b3 = "HOW_TO_DECRYPT.txt\x00" ascii
        $b4 = "\x00+notify /etc/motd\x00" ascii
        $b5 = "\x00+notify %s" ascii
        $b6 = "\x00+ prenotify %s" ascii
        $b7 = "\x00Stopping VMs\x00" ascii

    condition:
        (uint32(0) == 0x464C457F) and
        (
            (2 of ($h*)) or
            ((1 of ($a*)) and (2 of ($b*)))
        )
}


rule Hive_v5
{
    meta:
        author = "rivitna"
        family = "ransomware.hive"
        description = "Hive v5 ransomware Windows/Linux/ESXi payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 00 03 D0 FF 48 01 ?? 48 C1 EA 15 48 69 D2 00 01 D0 FF
                48 01 ?? 8A 04 ?? 32 04 ?? }
        $h1 = { 68 00 FF 2F 00 53 [8-18] 68 00 FD 2F 00 53 [20-32]
                8A 04 ?? 32 04 ?? }
        $h2 = { 8A 04 10 48 8B 94 24 ?? 0? 00 00 32 04 0A
                48 8B 8C 24 ?? 0? 00 00 30 04 29 48 FF C5
                49 39 E? 0F 85 ?? ?? FF FF }
        $h3 = { 8A 04 10 48 8B 8C 24 ?? 0? 00 00 32 04 ?? [0-8]
                ( 41 30 | 30 ) 04 2? 48 FF C5 49 39 E? [0-4]
                0F 85 ?? ?? FF FF }
        $h4 = { 8A 04 01 32 04 16 8B 54 24 ?? 8B B4 24 ?? 0? 00 00
                30 04 3A 47 39 7C 24 ?? 0F 85 ?? ?? FF FF }

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            (1 of ($h*))
        )
}
