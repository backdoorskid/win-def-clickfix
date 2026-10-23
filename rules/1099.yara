rule Trojan_Win32_Ofisus_B_2147731692_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\powershell.exe" wide //weight: 5
        $x_1_2 = "$SHeLLid[1]+$ShellId[13]+'x'" wide //weight: 1
        $x_1_3 = ")[1,3]+'X'-JoiN''" wide //weight: 1
        $x_1_4 = {24 00 50 00 73 00 48 00 4f 00 6d 00 45 00 5b 00 [0-4] 5d 00 2b 00 24 00 70 00 53 00 48 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 27 00 58 00 27 00}  //weight: 1, accuracy: Low
        $x_1_5 = {24 00 45 00 6e 00 56 00 3a 00 63 00 6f 00 6d 00 53 00 50 00 65 00 43 00 5b 00 [0-4] 2c 00 [0-4] 2c 00 [0-4] 5d 00 2d 00 4a 00 4f 00 69 00 4e 00 27 00 27 00}  //weight: 1, accuracy: Low
        $x_1_6 = {53 00 56 00 [0-8] 27 00 6f 00 46 00 73 00 27 00 [0-8] 27 00 [0-8] 27 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
