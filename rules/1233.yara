rule Trojan_Win32_PShellDlr_HL_2147943316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.HL!MTB"
        threat_id = "2147943316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 27 00 20 00 2b 00 20 00 24 00 [0-16] 5b 00 [0-4] 5d 00}  //weight: 100, accuracy: Low
        $x_100_2 = {30 00 78 00 36 00 39 00 [0-20] 30 00 78 00 36 00 35 00 [0-20] 30 00 78 00 37 00 38 00}  //weight: 100, accuracy: Low
        $x_1_3 = "-W HiDdEn -C" wide //weight: 1
        $x_1_4 = "-WindowStyle hidden -Command" wide //weight: 1
        $x_1_5 = "-w minimized -c" wide //weight: 1
        $x_1_6 = "-w 1" wide //weight: 1
        $x_1_7 = {e2 00 80 00 95 00 57 00 20 00 68 00 20 00 2d 00 63 00}  //weight: 1, accuracy: High
        $x_1_8 = "-w h -NoP -c" wide //weight: 1
        $x_1_9 = "-Window H" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}
