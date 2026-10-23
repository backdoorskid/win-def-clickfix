rule Trojan_Win32_PShellDlr_HA_2147940742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.HA!MTB"
        threat_id = "2147940742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "56"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 [0-4] 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-60] 2e 00 65 00 78 00 [0-4] 2c 00 24 00 64 00 29 00 3b 00}  //weight: 50, accuracy: Low
        $x_5_2 = {2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 24 00 64 00 3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 [0-80] 2e 00 65 00 78 00 [0-4] 3b 00}  //weight: 5, accuracy: Low
        $x_1_3 = "start-process $d;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
