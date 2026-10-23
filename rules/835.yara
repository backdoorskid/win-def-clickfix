rule Trojan_Win32_FileFix_HD_2147950995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HD!MTB"
        threat_id = "2147950995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_50_1 = " # " wide //weight: 50
        $x_50_2 = "  c:\\" wide //weight: 50
        $x_50_3 = "  h:\\" wide //weight: 50
        $x_50_4 = "  d:\\" wide //weight: 50
        $x_5_5 = ".pdf" wide //weight: 5
        $x_5_6 = ".xls" wide //weight: 5
        $x_5_7 = ".doc" wide //weight: 5
        $x_5_8 = ".ppt" wide //weight: 5
        $x_1_9 = "curl " wide //weight: 1
        $x_1_10 = "powershell" wide //weight: 1
        $x_2_11 = "http" wide //weight: 2
        $x_2_12 = " ping " wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}
