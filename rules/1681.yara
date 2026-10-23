rule Trojan_Win32_SuspPosLoadz_ZI_2147979967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPosLoadz.ZI!MTB"
        threat_id = "2147979967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Get-Random" wide //weight: 1
        $x_1_2 = "[char]$_" wide //weight: 1
        $x_1_3 = "WebClient" wide //weight: 1
        $x_1_4 = "$env:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
