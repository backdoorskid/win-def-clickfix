rule Trojan_Win32_PShellDlr_SC_2147931676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SC"
        threat_id = "2147931676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = ").invoke(" wide //weight: 10
        $x_10_4 = ").value|foreach" wide //weight: 10
        $x_1_5 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
