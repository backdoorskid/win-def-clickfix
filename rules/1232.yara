rule Trojan_Win32_PShellDlr_HK_2147943315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.HK!MTB"
        threat_id = "2147943315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2f 00 6d 00 69 00 6e 00 20 00 21 00 [0-22] 6c 00}  //weight: 100, accuracy: Low
        $x_50_2 = "=pow&" wide //weight: 50
        $x_50_3 = "=ers&" wide //weight: 50
        $x_1_4 = ".downloadstring" wide //weight: 1
        $x_5_5 = "iex $" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}
