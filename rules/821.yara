rule Trojan_Win32_FileFix_DT_2147947978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DT!MTB"
        threat_id = "2147947978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "161"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Powershell" wide //weight: 100
        $x_50_2 = "C:\\company\\" wide //weight: 50
        $x_50_3 = "C:\\internal-secure\\" wide //weight: 50
        $x_10_4 = ".docx" wide //weight: 10
        $x_10_5 = ".pdf" wide //weight: 10
        $x_10_6 = ".txt" wide //weight: 10
        $x_10_7 = ".ppt" wide //weight: 10
        $x_1_8 = " # " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}
