rule Trojan_Win32_PShellDlr_SB_2147838602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SB"
        threat_id = "2147838602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-32] 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
