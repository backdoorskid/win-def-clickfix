rule Trojan_Win32_LummaStealerClick_AB_2147932739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.AB!MTB"
        threat_id = "2147932739"
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
        $x_10_2 = "$env:" wide //weight: 10
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "invoke-expression $" wide //weight: 1
        $x_10_5 = "useragent" wide //weight: 10
        $x_10_6 = ".php?" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
