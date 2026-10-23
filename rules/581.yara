rule Trojan_Win32_Amadey_ZB_2147942699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZB!MTB"
        threat_id = "2147942699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String(" wide //weight: 1
        $x_1_2 = "Invoke-Expression $" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
