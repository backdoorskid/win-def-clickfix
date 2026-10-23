rule Trojan_Win32_Amadey_ZAC_2147945136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZAC!MTB"
        threat_id = "2147945136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::GetTotalMemory($" wide //weight: 1
        $x_1_2 = ".ReaDTOeNd(" wide //weight: 1
        $x_1_3 = "froMBASE64strinG(" wide //weight: 1
        $x_1_4 = "-join" wide //weight: 1
        $x_1_5 = "char[]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
