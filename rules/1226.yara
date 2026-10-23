rule Trojan_Win32_PShellDlr_SG_2147937656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SG!MTB"
        threat_id = "2147937656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1110"
        strings_accuracy = "Low"
    strings:
        $x_500_1 = "powershell" wide //weight: 500
        $x_500_2 = "net.webclient" wide //weight: 500
        $x_10_3 = "invoke" wide //weight: 10
        $x_10_4 = "join" wide //weight: 10
        $x_100_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 100, accuracy: Low
        $x_100_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 78 00 79 00 7a 00}  //weight: 100, accuracy: Low
        $x_100_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 100, accuracy: Low
        $x_100_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 100, accuracy: Low
        $x_100_9 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 6c 00 61 00 74 00}  //weight: 100, accuracy: Low
        $x_100_10 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00}  //weight: 100, accuracy: Low
        $x_100_11 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 74 00 6f 00 64 00 61 00 79 00}  //weight: 100, accuracy: Low
        $x_100_12 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 77 00 6f 00 72 00 6c 00 64 00}  //weight: 100, accuracy: Low
        $x_100_13 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 69 00 63 00 75 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 6 of ($x_100_*) and 1 of ($x_10_*))) or
            ((1 of ($x_500_*) and 7 of ($x_100_*))) or
            ((2 of ($x_500_*) and 1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_500_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}
