rule Trojan_Win32_LummaStealerClick_C_2147933474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.C!MTB"
        threat_id = "2147933474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "[io.path]::gettemppath(" wide //weight: 10
        $x_10_3 = "start-process -filepath $" wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
        $x_10_5 = "foreach ($" wide //weight: 10
        $x_1_6 = "invoke-webrequest -uri $" wide //weight: 1
        $x_1_7 = "iwr -uri $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
