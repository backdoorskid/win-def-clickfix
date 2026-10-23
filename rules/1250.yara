rule Trojan_Win32_Qakbot_DA_2147782538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DA"
        threat_id = "2147782538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 2e 00 2e 00 5c 00 [0-32] 2c 00 64 00 6c 00 6c 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 73 00 65 00 72 00 76 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 2e 00 2e 00 5c 00 [0-32] 2c 00 73 00 74 00 61 00 72 00 74 00 77 00}  //weight: 1, accuracy: Low
        $x_1_3 = "regsvr32 -s ..\\" wide //weight: 1
        $x_1_4 = "regsvr32 ..\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}
