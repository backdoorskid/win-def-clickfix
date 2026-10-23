rule Trojan_Win32_LummaStealerClick_R_2147933212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.R!MTB"
        threat_id = "2147933212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "where-object{$" wide //weight: 10
        $x_10_3 = "[scriptblock]::create" wide //weight: 10
        $x_10_4 = "]::cmdlet)net." wide //weight: 10
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = ".shop" wide //weight: 1
        $x_1_7 = ".xyz" wide //weight: 1
        $x_1_8 = ".biz" wide //weight: 1
        $x_1_9 = ".cyou" wide //weight: 1
        $x_1_10 = ".click" wide //weight: 1
        $x_1_11 = ".lat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
