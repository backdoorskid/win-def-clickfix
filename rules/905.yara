rule Trojan_Win32_LummaStealerClick_D_2147931675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.D!MTB"
        threat_id = "2147931675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[system.io.file]::create($" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "$env:computername" wide //weight: 10
        $x_1_4 = "invoke-webrequest $" wide //weight: 1
        $x_1_5 = "iwr $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
